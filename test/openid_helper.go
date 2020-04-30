package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// A Helper for testing OpenID authenticated endpints
//
// The general auth flow is
//   1. InitiateAuthFlow - Visit protect page with no auth
//   2. GetLoginPage - Get Login Page with info retrived from step 1
//   3. LoginToProvider - Post to Login Page
//   4. LoginToProtecedSite - Use provider login response to login to protected site
//   5. RetrieveProtectedPage - Use protected site login to retrieve protected page
// The helper method Authenticate will complete steps 1-4 for you, then you can retrieve pages with GetProtectedPage
//
// The logout flow is (assuming auth has already been completed)
//   1. InitiateLogout - Visit logout url in protected site
//   2. CompleteLogout - Get provider logout page

type OpenIDHelper struct {
	ProtectedUrl            string
	HttpClient              *http.Client
	InitiatorResponse       *OpenIDResponse
	GetLoginResponse        *OpenIDResponse
	ProviderLoginResponse   *OpenIDResponse
	ProtectedLoginResponse  *OpenIDResponse
	LogoutInitiatorResponse *OpenIDResponse
	CompleteLogoutResponse  *OpenIDResponse
}

type OpenIDResponse struct {
	Response   *http.Response
	Body       []byte
	Headers    http.Header
	StatusCode int
}

type LoginItems struct {
	FormAction string
	FormFields map[string]string
}

func NewOpenIDHelper(protectedUrl string) (*OpenIDHelper, error) {
	cookieJar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return nil, err
	}

	helper := &OpenIDHelper{
		ProtectedUrl: protectedUrl,
		HttpClient: &http.Client{
			// By default, Go does not impose a timeout, so an HTTP connection attempt can hang for a LONG time.
			Timeout: 10 * time.Second,
			Jar:     cookieJar,
		},
	}

	return helper, nil
}

func (openIDHelper *OpenIDHelper) Authenticate(username, password string) (*OpenIDResponse, error) {
	_, err := openIDHelper.InitiateAuthFlow()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to initiate openid auth flow: %s", err))
	}

	_, err = openIDHelper.GetLoginPage()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to get openid auth login page: %s", err))
	}

	_, err = openIDHelper.LoginToProvider(username, password)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to get login to openid provider: %s", err))
	}

	response, err := openIDHelper.LoginToProtectedSite()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to login to protected site: %s", err))
	}

	return response, nil
}

// Initiates the whole login flow by visiting the protected URL with no auth.
// Only gets the redirect and stops
func (openIDHelper *OpenIDHelper) InitiateAuthFlow() (*OpenIDResponse, error) {
	openIDHelper.HttpClient.CheckRedirect = doNotRedirect

	req, err := http.NewRequest("GET", openIDHelper.ProtectedUrl, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "*/*")

	resp, err := openIDHelper.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// We have done our redirect manipulation, return the client to normal behaviour
	openIDHelper.HttpClient.CheckRedirect = nil

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	openIDHelper.InitiatorResponse = &OpenIDResponse{
		Response:   resp,
		Body:       body,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}

	return openIDHelper.InitiatorResponse, nil
}

func (openIDHelper *OpenIDHelper) GetLoginPage() (*OpenIDResponse, error) {
	loginUrl, err := getRedirectLocation(openIDHelper.InitiatorResponse)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Auth flow initiation was not valid: %s", err))
	}

	openIDHelper.GetLoginResponse, err = openIDHelper.getUrl(loginUrl)
	if err != nil {
		return nil, err
	}

	return openIDHelper.GetLoginResponse, nil
}

func (openIDHelper *OpenIDHelper) LoginToProvider(username, password string) (*OpenIDResponse, error) {
	if openIDHelper.GetLoginResponse == nil {
		return nil, errors.New("Can't login until login page has been retrieved")
	}

	if openIDHelper.GetLoginResponse.StatusCode != 200 {
		return nil, errors.New("Getting the login page was not OK, cannot login")
	}

	openIDHelper.HttpClient.CheckRedirect = doNotRedirect

	loginItems, err := extractLoginItems(openIDHelper.GetLoginResponse, username, password)
	if err != nil {
		return nil, err
	}

	postData := url.Values{}
	for name, value := range loginItems.FormFields {
		postData.Add(name, value)
	}

	postBody := strings.NewReader(postData.Encode())

	req, err := http.NewRequest("POST", loginItems.FormAction, postBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := openIDHelper.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// We have done our redirect manipulation, return the client to normal behaviour
	openIDHelper.HttpClient.CheckRedirect = nil

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	openIDHelper.ProviderLoginResponse = &OpenIDResponse{
		Response:   resp,
		Body:       body,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}

	return openIDHelper.ProviderLoginResponse, nil
}

func (openIDHelper *OpenIDHelper) LoginToProtectedSite() (*OpenIDResponse, error) {
	loginUrl, err := getRedirectLocation(openIDHelper.ProviderLoginResponse)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Provider Login was not valid: %s", err))
	}

	openIDHelper.HttpClient.CheckRedirect = doNotRedirect

	openIDHelper.ProtectedLoginResponse, err = openIDHelper.getUrl(loginUrl)
	if err != nil {
		return nil, err
	}

	openIDHelper.HttpClient.CheckRedirect = nil

	return openIDHelper.ProtectedLoginResponse, nil
}

func (openIDHelper *OpenIDHelper) GetProtectedPage(url string) (*OpenIDResponse, error) {
	_, err := getRedirectLocation(openIDHelper.ProtectedLoginResponse)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Protected Login was not valid: %s", err))
	}

	openIDHelper.HttpClient.CheckRedirect = doNotRedirect

	response, err := openIDHelper.getUrl(url)
	if err != nil {
		return nil, err
	}

	openIDHelper.HttpClient.CheckRedirect = nil

	return response, nil
}

func (openIDHelper *OpenIDHelper) InitiateLogout(serverUrl string, redirectUrl string) (*OpenIDResponse, error) {
	_, err := getRedirectLocation(openIDHelper.ProtectedLoginResponse)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Protected Login was not valid, can't logout: %s", err))
	}

	// The full logout url is of the form: http://host/redirect_uri?logout=<urlencoded_url_to_redirect_back_to>
	// e.g. http://127.0.0.1:8380/redirect_uri?logout=http%3A%2F%2F127.0.0.1%3A8380%2Floggedout.php
	encodedRedirectUrl := url.QueryEscape(redirectUrl)
	logoutUrl := fmt.Sprintf("%s?logout=%s", serverUrl, encodedRedirectUrl)

	openIDHelper.LogoutInitiatorResponse, err = openIDHelper.GetProtectedPage(logoutUrl)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Couldn't get logout page: %s", err))
	}

	return openIDHelper.LogoutInitiatorResponse, nil
}

func (openIDHelper *OpenIDHelper) CompleteLogout() (*OpenIDResponse, error) {
	providerLogoutUrl, err := getRedirectLocation(openIDHelper.LogoutInitiatorResponse)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Protected Login was not valid, can't logout: %s", err))
	}

	openIDHelper.HttpClient.CheckRedirect = doNotRedirect

	openIDHelper.CompleteLogoutResponse, err = openIDHelper.getUrl(providerLogoutUrl)
	if err != nil {
		return nil, err
	}

	openIDHelper.HttpClient.CheckRedirect = nil

	return openIDHelper.CompleteLogoutResponse, nil
}

func (openIDHelper *OpenIDHelper) getUrl(url string) (*OpenIDResponse, error) {
	resp, err := openIDHelper.HttpClient.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	response := &OpenIDResponse{
		Response:   resp,
		Body:       body,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}

	return response, nil
}

func getRedirectLocation(response *OpenIDResponse) (string, error) {
	if response == nil {
		return "", errors.New("Previous request not completed")
	}

	if response.StatusCode != 302 {
		return "", errors.New("Previous request did not give a 302 redirect")
	}

	if len(response.Headers["Location"]) != 1 {
		return "", errors.New("Previous request did not provide exactly 1 Location header")
	}

	return response.Headers["Location"][0], nil
}

func extractLoginItems(getLoginResponse *OpenIDResponse, username, password string) (*LoginItems, error) {
	document, err := goquery.NewDocumentFromReader(bytes.NewReader(getLoginResponse.Body))
	if err != nil {
		return nil, err
	}

	form := document.Find("form")
	if form.Length() != 1 {
		return nil, errors.New("Wrong number of forms found on login page")
	}

	action, actionExists := form.Attr("action")
	if !actionExists {
		return nil, errors.New("Login form missing action attribute")
	}

	credentialId := form.Find("input[name=credentialId]")
	if credentialId.Length() != 1 {
		return nil, errors.New("Wrong number of credentialId inputs found on login form")
	}
	credentialIdValue := credentialId.AttrOr("value", "")

	loginItems := &LoginItems{
		FormAction: action,
		FormFields: map[string]string{
			"username":     username,
			"password":     password,
			"credentialId": credentialIdValue,
		},
	}

	return loginItems, nil
}

func doNotRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}
