package spec

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Songmu/retry"
	"github.com/mackerelio/golib/logging"
	"github.com/mackerelio/mackerel-client-go"

	"github.com/mackerelio/mackerel-agent/config"
)

// This Generator collects metadata about cloud instances.
// Currently EC2 and GCE are supported.
// EC2: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AESDG-chapter-instancedata.html
// GCE: https://developers.google.com/compute/docs/metadata
// AzureVM: https://docs.microsoft.com/azure/virtual-machines/virtual-machines-instancemetadataservice-overview

// CloudGenerator definition
type CloudGenerator struct {
	CloudMetaGenerator
}

// CloudMetaGenerator interface of metadata generator for each cloud platform
type CloudMetaGenerator interface {
	Generate() (interface{}, error)
	SuggestCustomIdentifier() (string, error)
}

var cloudLogger = logging.GetLogger("spec.cloud")

var ec2BaseURL, gceMetaURL, azureVMBaseURL *url.URL

func init() {
	ec2BaseURL, _ = url.Parse("http://169.254.169.254")
	gceMetaURL, _ = url.Parse("http://metadata.google.internal./computeMetadata/v1/?recursive=true")
	azureVMBaseURL, _ = url.Parse("http://169.254.169.254/metadata/instance")
}

var timeout = 3 * time.Second

// SuggestCloudGenerator returns suitable CloudGenerator
func SuggestCloudGenerator(conf *config.Config) *CloudGenerator {
	// if CloudPlatform is specified, return corresponding one
	switch conf.CloudPlatform {
	case config.CloudPlatformNone:
		return nil
	case config.CloudPlatformEC2:
		return &CloudGenerator{newEC2Generator(ec2BaseURL)}
	case config.CloudPlatformGCE:
		return &CloudGenerator{&GCEGenerator{gceMetaURL}}
	case config.CloudPlatformAzureVM:
		return &CloudGenerator{&AzureVMGenerator{azureVMBaseURL}}
	}

	var wg sync.WaitGroup
	gCh := make(chan *CloudGenerator, 3)

	// cancelable context
	ctx, cancel := context.WithCancel(context.Background())

	wg.Add(3)
	go func() {
		if isEC2(ctx) {
			gCh <- &CloudGenerator{newEC2Generator(ec2BaseURL)}
			cancel()
		}
		wg.Done()
	}()
	go func() {
		if isGCE(ctx) {
			gCh <- &CloudGenerator{&GCEGenerator{gceMetaURL}}
			cancel()
		}
		wg.Done()
	}()
	go func() {
		if isAzure(ctx) {
			gCh <- &CloudGenerator{&AzureVMGenerator{azureVMBaseURL}}
			cancel()
		}
		wg.Done()
	}()

	go func() {
		wg.Wait()
		// close so that `<-gCh` will receive nul
		close(gCh)
	}()

	return <-gCh
}

func httpCli() *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// don't use HTTP_PROXY when requesting cloud instance metadata APIs
			Proxy: nil,
		},
	}
}

func isGCE(ctx context.Context) bool {
	err := retry.WithContext(ctx, 2, 2*time.Second, func() error {
		_, err := requestGCEMeta(ctx)
		return err
	})
	return err == nil
}

// Note: May want to check without using the API.
func isAzure(ctx context.Context) bool {
	isAzure := false
	err := retry.WithContext(ctx, 2, 2*time.Second, func() error {
		cl := httpCli()
		// '/vmId` is probably Azure VM specific URL
		req, err := http.NewRequest("GET", azureVMBaseURL.String()+"/compute/vmId?api-version=2017-04-02&format=text", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Metadata", "true")

		resp, err := cl.Do(req.WithContext(ctx))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		isAzure = resp.StatusCode == 200
		return nil
	})
	return err == nil && isAzure
}

func requestGCEMeta(ctx context.Context) ([]byte, error) {
	cl := httpCli()
	req, err := http.NewRequest("GET", gceMetaURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := cl.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to request gce meta. response code: %d", resp.StatusCode)
	}
	return ioutil.ReadAll(resp.Body)
}

// EC2Generator meta generator for EC2
type EC2Generator struct {
	metadataClient *EC2MetadataClient
}

func newEC2Generator(baseURL *url.URL) *EC2Generator {
	return &EC2Generator{
		metadataClient: &EC2MetadataClient{
			client:  httpCli(),
			baseURL: baseURL,
		},
	}
}

// Generate collects metadata from cloud platform.
func (g *EC2Generator) Generate() (interface{}, error) {
	metadataKeys := []string{
		"instance-id",
		"instance-type",
		"placement/availability-zone",
		"security-groups",
		"ami-id",
		"hostname",
		"local-hostname",
		"public-hostname",
		"local-ipv4",
		"public-ipv4",
		"reservation-id",
	}

	metadata := make(map[string]string)

	for _, key := range metadataKeys {
		resp, err := g.metadataClient.Get(context.TODO(), "/latest/metadata/"+key)
		if err != nil {
			cloudLogger.Debugf("This host may not be running on EC2. Error while reading '%s'", key)
			return nil, nil
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				cloudLogger.Errorf("Results of requesting metadata cannot be read: '%s'", err)
				break
			}
			metadata[key] = string(body)
			cloudLogger.Debugf("results %s:%s", key, string(body))
		} else {
			cloudLogger.Debugf("Status code of the result of requesting metadata '%s' is '%d'", key, resp.StatusCode)
		}
	}

	return &mackerel.Cloud{Provider: "ec2", MetaData: metadata}, nil
}

// SuggestCustomIdentifier suggests the identifier of the EC2 instance
func (g *EC2Generator) SuggestCustomIdentifier() (string, error) {
	identifier := ""
	err := retry.Retry(3, 2*time.Second, func() error {
		key := "instance-id"
		resp, err := g.metadataClient.Get(context.TODO(), "/latest/metadata/"+key)
		if err != nil {
			return fmt.Errorf("error while retrieving instance-id")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("failed to request instance-id. response code: %d", resp.StatusCode)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("results of requesting instance-id cannot be read: '%s'", err)
		}
		instanceID := string(body)
		if instanceID == "" {
			return fmt.Errorf("invalid instance id")
		}
		identifier = instanceID + ".ec2.amazonaws.com"
		return nil
	})
	return identifier, err
}

// EC2MetadataClient handles HTTP request to EC2 Instance Metadata Service v2
// https://aws.amazon.com/jp/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/
type EC2MetadataClient struct {
	client               *http.Client
	baseURL              *url.URL
	cachedToken          string
	cachedTokenExpiredAt *time.Time
}

// Get requests to the specified path with following procedure:
// - If IMDSv2 token is not obtained yet or expired, obtain one (and store to cache)
// - Do the requested HTTP request with token
// - If the request failed with Unauthenticaed error, refresh the token and retry once
func (c *EC2MetadataClient) Get(ctx context.Context, path string) (*http.Response, error) {
	resp, err := c.getInternal(ctx, path, false)

	// 401 will be returned when the token has expired, so in the case retry once
	if err != nil && resp.StatusCode == http.StatusUnauthorized {
		return c.getInternal(ctx, path, true)
	}
	return resp, err
}

func (c *EC2MetadataClient) getInternal(ctx context.Context, path string, forceRefresh bool) (*http.Response, error) {
	// obtain token
	token, err := c.getToken(ctx, forceRefresh)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL.String()+path, nil)
	req.Header.Set("X-aws-ec2-metadata-token", token)
	if err != nil {
		cloudLogger.Errorf("Failed to build EC2 Metadata request: '%s'", err)
		return nil, err
	}
	return c.client.Do(req)
}

func (c *EC2MetadataClient) getToken(ctx context.Context, forceRefresh bool) (string, error) {
	// If forceRefresh is not specified and the cached token *seems* still usable, return the cached one
	if !forceRefresh && c.cachedToken != "" && c.cachedTokenExpiredAt != nil && c.cachedTokenExpiredAt.After(time.Now()) {
		return c.cachedToken, nil
	}
	token, expiredAt, err := c.getTokenInternal(ctx)
	if err != nil {
		return "", err
	}
	c.cachedToken = token
	c.cachedTokenExpiredAt = expiredAt

	return token, nil
}

func (c *EC2MetadataClient) getTokenInternal(ctx context.Context) (string, *time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, "PUT", c.baseURL.String()+"/latest/api/token", nil)
	if err != nil {
		cloudLogger.Errorf("Failed to build EC2 Metadata Token request: '%s'", err)
		return "", nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")

	requestedAt := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		cloudLogger.Errorf("Failed to request EC2 Metadata Token: '%s'", err)
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		cloudLogger.Errorf("Failed to request EC2 Metadata Token request: '%s'", err)
		return "", nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		cloudLogger.Errorf("Failed to read response of EC2 Metadata Token request: '%s'", err)
		return "", nil, err
	}

	ttlSeconds, err := strconv.Atoi(resp.Header.Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds"))
	if err != nil {
		cloudLogger.Errorf("Failed to parse ttl response header of EC2 Metadata Token request: '%s'", err)
		return "", nil, err
	}
	// Note that this expiredAt MAY not be accurate, but at least it should be earlier the accurate one.
	expiredAt := requestedAt.Add(time.Second * time.Duration(ttlSeconds))

	return string(body), &expiredAt, nil
}

// GCEGenerator generate for GCE
type GCEGenerator struct {
	metaURL *url.URL
}

// Generate collects metadata from cloud platform.
func (g *GCEGenerator) Generate() (interface{}, error) {
	bytes, err := requestGCEMeta(context.Background())
	if err != nil {
		return nil, err
	}
	var data gceMeta
	json.Unmarshal(bytes, &data)
	return data.toGeneratorResults(), nil
}

type gceInstance struct {
	Zone         string
	InstanceType string `json:"machineType"`
	Hostname     string
	InstanceID   uint64 `json:"id"`
}

type gceProject struct {
	ProjectID        string
	NumericProjectID uint64
}

type gceMeta struct {
	Instance *gceInstance
	Project  *gceProject
}

func (g gceMeta) toGeneratorMeta() map[string]string {
	meta := make(map[string]string)

	lastS := func(s string) string {
		ss := strings.Split(s, "/")
		return ss[len(ss)-1]
	}

	if ins := g.Instance; ins != nil {
		meta["hostname"] = ins.Hostname
		meta["instance-id"] = fmt.Sprint(ins.InstanceID)
		meta["instance-type"] = lastS(ins.InstanceType)
		meta["zone"] = lastS(ins.Zone)
	}

	if proj := g.Project; proj != nil {
		meta["projectId"] = proj.ProjectID
	}

	return meta
}

func (g gceMeta) toGeneratorResults() *mackerel.Cloud {
	return &mackerel.Cloud{Provider: "gce", MetaData: g.toGeneratorMeta()}
}

// SuggestCustomIdentifier for GCE is not implemented yet
func (g *GCEGenerator) SuggestCustomIdentifier() (string, error) {
	return "", nil
}

// AzureVMGenerator meta generator for Azure VM
type AzureVMGenerator struct {
	baseURL *url.URL
}

// Generate collects metadata from cloud platform.
func (g *AzureVMGenerator) Generate() (interface{}, error) {
	metadataComputeKeys := map[string]string{
		"location":  "location",
		"offer":     "imageReferenceOffer",
		"osType":    "osSystemType",
		"publisher": "imageReferencePublisher",
		"sku":       "imageReferenceSku",
		"vmId":      "vmID",
		"vmSize":    "virtualMachineSizeType",
	}

	ipAddressKeys := map[string]string{
		"privateIpAddress": "privateIpAddress",
		"publicIpAddress":  "publicIpAddress",
	}

	metadata := make(map[string]string)
	metadata = retrieveAzureVMMetadata(metadata, g.baseURL.String(), "/compute/", metadataComputeKeys)
	metadata = retrieveAzureVMMetadata(metadata, g.baseURL.String(), "/network/interface/0/ipv4/ipAddress/0/", ipAddressKeys)

	return &mackerel.Cloud{Provider: "AzureVM", MetaData: metadata}, nil
}

func retrieveAzureVMMetadata(metadataMap map[string]string, baseURL string, urlSuffix string, keys map[string]string) map[string]string {
	cl := httpCli()

	for key, value := range keys {
		req, err := http.NewRequest("GET", baseURL+urlSuffix+key+"?api-version=2017-04-02&format=text", nil)
		if err != nil {
			cloudLogger.Debugf("This host may not be running on Azure VM. Error while reading '%s'", key)
			return metadataMap
		}

		req.Header.Set("Metadata", "true")

		resp, err := cl.Do(req)
		if err != nil {
			cloudLogger.Debugf("This host may not be running on Azure VM. Error while reading '%s'", key)
			return metadataMap
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				cloudLogger.Errorf("Results of requesting metadata cannot be read: '%s'", err)
				break
			}
			metadataMap[value] = string(body)
			cloudLogger.Debugf("results %s:%s", key, string(body))
		} else {
			cloudLogger.Debugf("Status code of the result of requesting metadata '%s' is '%d'", key, resp.StatusCode)
		}
	}
	return metadataMap
}

// SuggestCustomIdentifier suggests the identifier of the Azure VM instance
func (g *AzureVMGenerator) SuggestCustomIdentifier() (string, error) {
	identifier := ""
	err := retry.Retry(3, 2*time.Second, func() error {
		cl := httpCli()
		req, err := http.NewRequest("GET", azureVMBaseURL.String()+"/compute/vmId?api-version=2017-04-02&format=text", nil)
		if err != nil {
			return fmt.Errorf("error while retrieving vmId")
		}
		req.Header.Set("Metadata", "true")

		resp, err := cl.Do(req)
		if err != nil {
			return fmt.Errorf("error while retrieving vmId")
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return fmt.Errorf("failed to request vmId. response code: %d", resp.StatusCode)
		}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("results of requesting vmId cannot be read: '%s'", err)
		}
		instanceID := string(body)
		if instanceID == "" {
			return fmt.Errorf("invalid instance id")
		}
		identifier = instanceID + ".virtual_machine.azure.microsoft.com"
		return nil
	})
	return identifier, err
}
