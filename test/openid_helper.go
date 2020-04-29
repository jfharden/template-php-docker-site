package main

import (
	"io/ioutil"
	"net/http"
	"time"
)

// A Helper for testing OpenID authenticated endpints
//
// The general auth flow is
//   1. InitiateAuthFlow - Visit protect page with no auth
//   2. GetLoginPage - Get Login Page with info retrived from step 1
//   3. LoginToProvider - Post to Login Page
//   4. RetrieveProtectedPage - Use the info returned from the Login post to get the protected page
type OpenIDHelper struct {
	ProtectedUrl      string
	InitiatorResponse *InitiatorResponse
}

type InitiatorResponse struct {
	Response   *http.Response
	Body       []byte
	Headers    http.Header
	StatusCode int
}

// Initiates the whole login flow by visiting the protected URL with no auth.
// Only gets the redirect and stops
func (openIDHelper *OpenIDHelper) InitiateAuthFlow() (*InitiatorResponse, error) {
	client := http.Client{
		// By default, Go does not impose a timeout, so an HTTP connection attempt can hang for a LONG time.
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", openIDHelper.ProtectedUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	initiatorResponse := &InitiatorResponse{
		Response:   resp,
		Body:       body,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}

	openIDHelper.InitiatorResponse = initiatorResponse

	return initiatorResponse, nil
}
