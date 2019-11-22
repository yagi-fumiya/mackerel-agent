package spec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func setEc2BaseURL(url *url.URL) func() {
	oldEC2BaseURL := ec2BaseURL
	ec2BaseURL = url
	return func() {
		ec2BaseURL = oldEC2BaseURL // restore value
	}
}

func TestIsEC2UUID(t *testing.T) {
	tests := []struct {
		uuid   string
		expect bool
	}{
		{"ec2e1916-9099-7caf-fd21-01234abcdef", true},
		{"EC2E1916-9099-7CAF-FD21-01234ABCDEF", true},
		{"45e12aec-dcd1-b213-94ed-01234abcdef", true}, // litte endian
		{"45E12AEC-DCD1-B213-94ED-01234ABCDEF", true}, // litte endian
		{"abcd1916-9099-7caf-fd21-01234abcdef", false},
		{"ABCD1916-9099-7CAF-FD21-01234ABCDEF", false},
		{"", false},
	}

	for _, tc := range tests {
		if isEC2UUID(tc.uuid) != tc.expect {
			t.Errorf("isEC2() should be %v: %q", tc.expect, tc.uuid)
		}
	}
}

func TestIsEC2(t *testing.T) {
	tests := []struct {
		existsWmicRecords [2]bool
		statusCode        bool
		expect            bool
	}{
		{
			existsWmicRecords: [2]bool{
				true,
				true,
			},
			statusCode: 200,
			expect:     true,
		},
		{
			existsWmicRecords: [2]bool{
				false,
				true,
			},
			statusCode: 200,
			expect:     true,
		},
		{
			existsWmicRecords: [2]bool{
				true,
				false,
			},
			statusCode: 200,
			expect:     true,
		},
		{
			existsWmicRecords: [2]bool{
				false,
				false,
			},
			statusCode: 200,
			expect:     false,
		},
		{
			existsWmicRecords: [2]bool{
				true,
				true,
			},
			statusCode: 404,
			expect:     false,
		},
		{
			existsWmicRecords: [2]bool{
				true,
				true,
			},
			statusCode: 401,
			expect:     true,
		},
	}

	for _, tc := range tests {
		func() {
			handler := func(res http.ResponseWriter, req *http.Request) {
				res.WriteHeader(tc.statusCode)
			}
			ts := httptest.NewServer(http.HandlerFunc(handler))
			defer func() { ts.Close() }()

			u, _ := url.Parse(ts.URL)
			defer setEc2BaseURL(u)()

			wmiRecords := make([]Win32ComputerSystemProduct, 2)
			for i, exist := range tc.existsWmicRecords {
				if exist {
					wmiRecords[i].UUID = "ec2e1916-9099-7caf-fd21-012345abcdef" // valid EC2 UUID
				} else {
					wmiRecords[i].UUID = "ec1e1916-9099-7caf-fd21-012345abcdef" // invalid EC2 UUID
				}
			}

			if isEC2WithSpecifiedWmiRecords(context.Background(), wmiRecords) != tc.expect {
				t.Errorf("isEC2() should be %v: %#v", tc.expect, tc)
			}
		}()
	}
}
