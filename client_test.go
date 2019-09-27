package factom_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/AdamSLevy/jsonrpc2"
)

// TODO: Where can I stick something like this?

// GetClientWithFixedResp will return a client that no matter what the request is,
// will always respond with the 'resp' as the body.
// From http://hassansin.github.io/Unit-Testing-http-client-in-Go
func ClientWithFixedRPCResponse(result interface{}) *http.Client {
	client := NewTestClient(func(req *http.Request) *http.Response {
		var jReq jsonrpc2.Request
		reqData, _ := ioutil.ReadAll(req.Body)
		_ = json.Unmarshal(reqData, &jReq)

		resp := jsonrpc2.Response{
			Result: result,
			ID:     jReq.ID,
		}

		respData, _ := json.Marshal(resp)
		// Test request parameters
		return &http.Response{
			StatusCode: 200,
			// Send response to be tested
			Body: ioutil.NopCloser(bytes.NewBuffer(respData)),
			// Must be set to non-nil Value or it panics
			Header: make(http.Header),
		}
	})

	return client
}

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

//NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}
