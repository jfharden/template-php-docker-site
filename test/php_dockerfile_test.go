package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gruntwork-io/terratest/modules/docker"
	http_helper "github.com/gruntwork-io/terratest/modules/http-helper"
	"github.com/gruntwork-io/terratest/modules/logger"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/assert"
)

type PageStructureOptions struct {
	SearchTerm           string
	NumberOfResults      int
	SelectedSearchFields *SelectedSearchFields
	ResultRows           []*ResultRow
}

func NewPageStructureOptions(searchTerm string, numberOfResults int) *PageStructureOptions {
	return &PageStructureOptions{
		SearchTerm:           searchTerm,
		NumberOfResults:      numberOfResults,
		SelectedSearchFields: &SelectedSearchFields{},
		ResultRows:           []*ResultRow{},
	}
}

type ResultRow struct {
	DBID  string
	Title string
	Year  string
}

type SelectedSearchFields struct {
	Years   []string
	Ratings []string
	Genres  []string
	Types   []string
}

type SearchFieldQuery struct {
	Form           *goquery.Selection
	Name           string
	ValuesInclude  map[string]string
	SelectedValues []string
}

func TestDockerfile(t *testing.T) {
	waitForReady := func() { time.Sleep(10 * time.Second) }

	validators := []func(*testing.T){
		validateServerHeaderProd,
		validatePhpHardeningConfigApplied,
		validateDirectoryListingDenied,
		validateIndexOk,
	}

	runTestsWithDockerComposeFile(t, "docker-compose.yaml", validators, waitForReady)
}

func TestHtpasswdAuth(t *testing.T) {
	waitForReady := func() { time.Sleep(10 * time.Second) }

	validators := []func(*testing.T){
		validateRequiresAuth,
		validateUnauthorizedPageExcludesSignature,
		validateIndexOkHtpasswdAuth,
	}

	runTestsWithDockerComposeFile(t, "docker-compose.htpasswd.yaml", validators, waitForReady)
}

// func TestOpenIdAuth(t *testing.T) {
// 	// Keycloak tages an age to start up
// 	// TODO Make this wait more intelligent, can't live with this wait time!
// 	waitForReady := func() { time.Sleep(60 * time.Second) }
//
// 	validators := []func(*testing.T){
// 	}
//
// 	runTestsWithDockerComposeFile(t, "docker-compose.openid.yaml", validators, waitForReady)
// }

func runTestsWithDockerComposeFile(t *testing.T, dockerfile string, validators []func(*testing.T), waitForReady func()) {
	dockerOptions := &docker.Options{
		WorkingDir: "../",
	}

	defer test_structure.RunTestStage(t, "destroy", func() {
		docker.RunDockerCompose(t, dockerOptions, "-f", dockerfile, "down", "-v", "--rmi", "local")
	})

	test_structure.RunTestStage(t, "build", func() {
		docker.RunDockerCompose(t, dockerOptions, "-f", dockerfile, "build", "--no-cache", "--force-rm")
	})

	test_structure.RunTestStage(t, "launch", func() {
		docker.RunDockerCompose(t, dockerOptions, "-f", dockerfile, "up", "-d")

		// It takes postgres a while to complete startup, load the seeds and restart
		waitForReady()
	})

	test_structure.RunTestStage(t, "validate", func() {
		for _, validator := range validators {
			validator(t)
		}
	})
}

func validateRequiresAuth(t *testing.T) {
	statusCode, body := http_helper.HttpGet(t, "http://127.0.0.1/index.php", &tls.Config{})

	assert.Equal(t, 401, statusCode)
	assert.Contains(t, body, "Unauthorized")
}

func validateUnauthorizedPageExcludesSignature(t *testing.T) {
	statusCode, body := http_helper.HttpGet(t, "http://127.0.0.1/index.php", &tls.Config{})

	assert.Equal(t, 401, statusCode)
	assert.NotContains(t, body, "Apache")
}

func validateIndexOk(t *testing.T) {
	statusCode, _ := http_helper.HttpGet(t, "http://127.0.0.1/", &tls.Config{})

	assert.Equal(t, 200, statusCode)
}

func validateIndexOkHtpasswdAuth(t *testing.T) {
	statusCode, _ := http_helper.HttpGet(t, urlWithBasicAuth(""), &tls.Config{})

	assert.Equal(t, 200, statusCode)
}

func validateServerHeaderProd(t *testing.T) {
	headers := getHeaders(t, "http://127.0.0.1/index.php")

	serverHeaders := headers["Server"]

	assert.Equal(t, 1, len(serverHeaders), "Multiple Server headers returned")
	assert.Equal(t, "Apache", serverHeaders[0], "Server header reveals more then Apache")

	return
}

func validatePhpHardeningConfigApplied(t *testing.T) {
	headers := getHeaders(t, urlWithBasicAuth(""))

	poweredByHeaders := headers["X-Powered-By"]

	assert.Empty(t, poweredByHeaders, "X-Powdered-By was returned, PHP hardening config has not been applied")
}

func validateDirectoryListingDenied(t *testing.T) {
	statusCode, body := http_helper.HttpGet(t, urlWithBasicAuth("images/"), &tls.Config{})

	assert.Equal(t, 403, statusCode)
	assert.Contains(t, body, "Forbidden")
}

func getHeaders(t *testing.T, url string) http.Header {
	logger.Log(t, fmt.Sprintf("Making an HTTP GET call to URL %s", url))

	client := http.Client{
		// By default, Go does not impose a timeout, so an HTTP connection attempt can hang for a LONG time.
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Couldn't get URL %s", url)
	}

	// We don't care about the body here
	resp.Body.Close()

	return resp.Header
}

func urlWithBasicAuth(path string) string {
	return fmt.Sprintf("http://foo:bar@127.0.0.1/%s", path)
}
