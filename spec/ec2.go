package spec

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Songmu/retry"
	"github.com/mackerelio/golib/logging"
	"github.com/mackerelio/mackerel-client-go"
)

var ec2BaseURL *url.URL

func init() {
	ec2BaseURL, _ = url.Parse("http://169.254.169.254")
}

// EC2Generator meta generator for EC2
type EC2Generator struct {
	metadataClient *EC2MetadataClient
	logger         *logging.Logger
}

func newEC2Generator(baseURL *url.URL) *EC2Generator {
	return &EC2Generator{
		logger:         cloudLogger,
		metadataClient: newEC2MetadataClient(baseURL, cloudLogger),
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
			g.logger.Debugf("This host may not be running on EC2. Error while reading '%s'", key)
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
			g.logger.Debugf("results %s:%s", key, string(body))
		} else {
			g.logger.Debugf("Status code of the result of requesting metadata '%s' is '%d'", key, resp.StatusCode)
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

type ec2MetadataEndpointTokenCache struct {
	token     string
	expiredAt *time.Time
}

func (c *ec2MetadataEndpointTokenCache) expired(now time.Time) bool {
	if c.expiredAt == nil {
		return false
	}
	return now.After(*c.expiredAt)
}

// EC2MetadataClient handles HTTP request to EC2 Instance Metadata Service v2
// https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/
type EC2MetadataClient struct {
	client     *http.Client
	baseURL    *url.URL
	tokenCache *ec2MetadataEndpointTokenCache
	logger     *logging.Logger
}

func newEC2MetadataClient(baseURL *url.URL, logger *logging.Logger) *EC2MetadataClient {
	return &EC2MetadataClient{
		client:  httpCli(),
		baseURL: baseURL,
		logger:  logger,
	}
}

// Get requests to the specified path with following procedure:
// - If IMDSv2 token is not obtained yet or expired, obtain one (and store to cache)
// - Do the requested HTTP request with token
// - If the request failed with Unauthenticaed error, refresh the token and retry once
func (c *EC2MetadataClient) Get(ctx context.Context, path string) (*http.Response, error) {
	resp, err := c.getInternal(ctx, path)

	// 401 suggests token's expiration
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		c.fetchAndStoreToken(ctx)
		return c.getInternal(ctx, path)
	}
	return resp, err
}

func (c *EC2MetadataClient) getInternal(ctx context.Context, path string) (*http.Response, error) {
	// obtain token
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", c.baseURL.String()+path, nil)
	req.Header.Set("X-aws-ec2-metadata-token", token)
	if err != nil {
		c.logger.Errorf("Failed to build EC2 Metadata request: '%s'", err)
		return nil, err
	}
	return c.client.Do(req.WithContext((ctx)))
}

func (c *EC2MetadataClient) getToken(ctx context.Context) (string, error) {
	// If the cached token does not exist or expired, refresh it
	if c.tokenCache == nil || c.tokenCache.expired(time.Now()) {
		if err := c.fetchAndStoreToken(ctx); err != nil {
			return "", err
		}
	}
	return c.tokenCache.token, nil
}

func (c *EC2MetadataClient) fetchAndStoreToken(ctx context.Context) error {
	c.tokenCache = nil
	// There might be some EC2-compatible environments which does NOT support IMDSv2,
	// So we ignore HTTP request failures here and store empty (but not nil) token as cache
	req, err := http.NewRequest("PUT", c.baseURL.String()+"/latest/api/token", nil)
	if err != nil {
		c.logger.Errorf("Failed to build EC2 Metadata Token request: '%s'", err)
		return err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")

	requestedAt := time.Now()
	resp, err := c.client.Do(req.WithContext((ctx)))
	if err != nil {
		c.logger.Infof("(Ignored) Failed to request EC2 Metadata Token: '%s'", err)
		c.tokenCache = &ec2MetadataEndpointTokenCache{}
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.logger.Infof("(Ignored) Failed to request EC2 Metadata Token request: '%s'", err)
		c.tokenCache = &ec2MetadataEndpointTokenCache{}
		return nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.logger.Errorf("Failed to read response of EC2 Metadata Token request: '%s'", err)
		return err
	}

	ttlSeconds, err := strconv.Atoi(resp.Header.Get("X-Aws-Ec2-Metadata-Token-Ttl-Seconds"))
	if err != nil {
		c.logger.Errorf("Failed to parse ttl response header of EC2 Metadata Token request: '%s'", err)
		return err
	}
	// Note that this expiredAt MAY not be accurate, but at least it should be earlier the accurate one.
	expiredAt := requestedAt.Add(time.Second * time.Duration(ttlSeconds))

	c.tokenCache = &ec2MetadataEndpointTokenCache{
		token:     string(body),
		expiredAt: &expiredAt,
	}
	return nil
}
