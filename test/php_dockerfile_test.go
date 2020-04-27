package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	dockerOptions := &docker.Options{
		WorkingDir: "../",
	}

	defer test_structure.RunTestStage(t, "destroy", func() {
		docker.RunDockerCompose(t, dockerOptions, "down", "-v", "--rmi", "local")
	})

	test_structure.RunTestStage(t, "build", func() {
		docker.RunDockerCompose(t, dockerOptions, "build", "--no-cache", "--force-rm")
	})

	test_structure.RunTestStage(t, "launch", func() {
		docker.RunDockerCompose(t, dockerOptions, "up", "-d")

		// It takes postgres a while to complete startup, load the seeds and restart
		time.Sleep(10 * time.Second)
	})

	test_structure.RunTestStage(t, "validate", func() {
		validateRequiresAuth(t)
		validateUnauthorizedPageExcludesSignature(t)
		validateServerHeaderProd(t)
		validatePhpHardeningConfigApplied(t)
		validateDirectoryListingDenied(t)
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

func validateServerHeaderProd(t *testing.T) {
	headers := getHeaders(t, "http://127.0.0.1/index.php")

	serverHeaders := headers["Server"]

	assert.Equal(t, 1, len(serverHeaders), "Multiple Server headers returned")
	assert.Equal(t, "Apache", serverHeaders[0], "Server header reveals more then Apache")

	return
}

func validatePhpHardeningConfigApplied(t *testing.T) {
	headers := getHeaders(t, urlWithAuth(""))

	poweredByHeaders := headers["X-Powered-By"]

	assert.Empty(t, poweredByHeaders, "X-Powdered-By was returned, PHP hardening config has not been applied")
}

func validateDirectoryListingDenied(t *testing.T) {
	statusCode, body := http_helper.HttpGet(t, urlWithAuth("images/"), &tls.Config{})

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

func urlWithAuth(path string) string {
	return fmt.Sprintf("http://foo:bar@127.0.0.1/%s", path)
}
