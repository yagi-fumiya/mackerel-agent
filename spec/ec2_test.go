package spec

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mackerelio/mackerel-client-go"
)

func NewValidMockMetadataServer() *httptest.Server {
	pathToContent := map[string]string{
		"/latest/metadata/instance-id": "i-4f90d537",
	}
	handler := func(res http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/latest/api/token" {
			res.Header().Add("X-aws-Ec2-Metadata-Token-Ttl-Seconds", "60")
			fmt.Fprint(res, "a-dummy-token")
			return
		}
		if content, ok := pathToContent[req.URL.Path]; ok {
			fmt.Fprint(res, content)
			return
		}
		http.Error(res, "not found", http.StatusNotFound)
	}
	return httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		handler(res, req)
	}))
}

func TestEC2Generate(t *testing.T) {
	ts := NewValidMockMetadataServer()
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("should not raise error: %s", err)
	}

	g := newEC2Generator(u)

	value, err := g.Generate()
	if err != nil {
		t.Errorf("should not raise error: %s", err)
	}

	cloud, typeOk := value.(*mackerel.Cloud)
	if !typeOk {
		t.Errorf("value should be *mackerel.Cloud. %+v", value)
	}

	metadata, typeOk := cloud.MetaData.(map[string]string)
	if !typeOk {
		t.Errorf("MetaData should be map. %+v", cloud.MetaData)
	}

	if len(metadata["instance-id"]) == 0 {
		t.Error("instance-id should be filled")
	}
}

func TestEC2SuggestCustomIdentifier(t *testing.T) {
	i := 0
	threshold := 100
	handler := func(res http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/latest/metadata/instance-id" {
			if i < threshold {
				http.Error(res, "not found", http.StatusNotFound)
			} else {
				fmt.Fprint(res, "i-4f90d537")
			}
			i++
			return
		}
		if req.URL.Path == "/latest/api/token" {
			res.Header().Add("X-aws-Ec2-Metadata-Token-Ttl-Seconds", "60")
			fmt.Fprint(res, "a-dummy-token")
			return
		}
		http.Error(res, "not found", http.StatusNotFound)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		handler(res, req)
	}))
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Errorf("should not raise error: %s", err)
	}
	g := &CloudGenerator{newEC2Generator(u)}

	// 404, 404, 404 => give up
	{
		_, err := g.SuggestCustomIdentifier()
		if err == nil {
			t.Errorf("should raise error: %s", err)
		}
	}
	i = 0
	threshold = 0
	// 200 => ok
	{
		customIdentifier, err := g.SuggestCustomIdentifier()
		if err != nil {
			t.Errorf("should not raise error: %s", err)
		}
		if customIdentifier != "i-4f90d537.ec2.amazonaws.com" {
			t.Error("customIdentifier mismatch")
		}
	}
	i = 0
	threshold = 1
	// 404, 200 => ok
	{
		customIdentifier, err := g.SuggestCustomIdentifier()
		if err != nil {
			t.Errorf("should not raise error: %s", err)
		}
		if customIdentifier != "i-4f90d537.ec2.amazonaws.com" {
			t.Error("customIdentifier mismatch")
		}
	}
	i = 0
	threshold = 3
	// 404, 404, 404(give up), 200, ...
	{
		_, err := g.SuggestCustomIdentifier()
		if err == nil {
			t.Errorf("should raise error: %s", err)
		}
	}
}
