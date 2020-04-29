package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/docker"
	http_helper "github.com/gruntwork-io/terratest/modules/http-helper"
	"github.com/gruntwork-io/terratest/modules/logger"
	test_structure "github.com/gruntwork-io/terratest/modules/test-structure"
	"github.com/stretchr/testify/assert"
)

type RunTestOptions struct {
	DockerComposeFile string
	Validators        []func(*testing.T, *RunTestOptions)
	WaitForReady      func()
	EnvVars           map[string]string
}

func TestDockerfile(t *testing.T) {
	options := &RunTestOptions{
		DockerComposeFile: "docker-compose.yaml",
		Validators: []func(*testing.T, *RunTestOptions){
			validateServerHeaderProd,
			validatePhpHardeningConfigApplied,
			validateDirectoryListingDenied,
			validateIndexOk,
		},
		WaitForReady: func() { time.Sleep(10 * time.Second) },
		EnvVars: map[string]string{
			"HTTP_PORT":   "8180",
			"APP_IP":      "10.101.0.2",
			"APP_DB_IP":   "10.101.0.3",
			"SUBNET_CIDR": "10.101.0.0/24",
		},
	}

	runTestsWithDockerComposeFile(t, options)
}

func TestHtpasswdAuth(t *testing.T) {
	options := &RunTestOptions{
		DockerComposeFile: "docker-compose.htpasswd.yaml",
		Validators: []func(*testing.T, *RunTestOptions){
			validateRequiresAuth,
			validateUnauthorizedPageExcludesSignature,
			validateIndexOkHtpasswdAuth,
		},
		WaitForReady: func() { time.Sleep(10 * time.Second) },
		EnvVars: map[string]string{
			"HTTP_PORT":   "8280",
			"APP_IP":      "10.102.0.2",
			"APP_DB_IP":   "10.102.0.3",
			"SUBNET_CIDR": "10.102.0.0/24",
		},
	}

	runTestsWithDockerComposeFile(t, options)
}

// func TestOpenIdAuth(t *testing.T) {
// 	options := &RunTestOptions{
// 		DockerComposeFile: "docker-compose.openid.yaml",
// 		Validators:        []func(*testing.T){
// 		},
// 		// Keycloak tages an age to start up
// 		// TODO Make this wait more intelligent, can't live with this wait time!
// 		WaitForReady: func() { time.Sleep(60 * time.Second) },
// 		EnvVars:      map[string]string{},
// 	}
//
// 	runTestsWithDockerComposeFile(t, options)
// }

func runTestsWithDockerComposeFile(t *testing.T, options *RunTestOptions) {
	dockerOptions := &docker.Options{
		WorkingDir: "../",
		EnvVars:    options.EnvVars,
	}

	defer test_structure.RunTestStage(t, "destroy", func() {
		docker.RunDockerCompose(t, dockerOptions, "-f", options.DockerComposeFile, "down", "-v", "--rmi", "local")
	})

	test_structure.RunTestStage(t, "build", func() {
		docker.RunDockerCompose(t, dockerOptions, "-f", options.DockerComposeFile, "build", "--force-rm")
	})

	test_structure.RunTestStage(t, "launch", func() {
		docker.RunDockerCompose(t, dockerOptions, "-f", options.DockerComposeFile, "up", "-d")

		// It takes postgres a while to complete startup, load the seeds and restart
		options.WaitForReady()
	})

	test_structure.RunTestStage(t, "validate", func() {
		for _, validator := range options.Validators {
			validator(t, options)
		}
	})
}

func validateRequiresAuth(t *testing.T, options *RunTestOptions) {
	statusCode, body := http_helper.HttpGet(t, urlWithoutAuth(options, "index.php"), &tls.Config{})

	assert.Equal(t, 401, statusCode)
	assert.Contains(t, body, "Unauthorized")
}

func validateUnauthorizedPageExcludesSignature(t *testing.T, options *RunTestOptions) {
	statusCode, body := http_helper.HttpGet(t, urlWithoutAuth(options, "index.php"), &tls.Config{})

	assert.Equal(t, 401, statusCode)
	assert.NotContains(t, body, "Apache")
}

func validateIndexOk(t *testing.T, options *RunTestOptions) {
	statusCode, _ := http_helper.HttpGet(t, urlWithoutAuth(options, ""), &tls.Config{})

	assert.Equal(t, 200, statusCode)
}

func validateIndexOkHtpasswdAuth(t *testing.T, options *RunTestOptions) {
	statusCode, _ := http_helper.HttpGet(t, urlWithBasicAuth(options, ""), &tls.Config{})

	assert.Equal(t, 200, statusCode)
}

func validateServerHeaderProd(t *testing.T, options *RunTestOptions) {
	headers := getHeaders(t, urlWithoutAuth(options, "index.php"))

	serverHeaders := headers["Server"]

	assert.Equal(t, 1, len(serverHeaders), "Multiple Server headers returned")
	assert.Equal(t, "Apache", serverHeaders[0], "Server header reveals more then Apache")

	return
}

func validatePhpHardeningConfigApplied(t *testing.T, options *RunTestOptions) {
	headers := getHeaders(t, urlWithBasicAuth(options, ""))

	poweredByHeaders := headers["X-Powered-By"]

	assert.Empty(t, poweredByHeaders, "X-Powdered-By was returned, PHP hardening config has not been applied")
}

func validateDirectoryListingDenied(t *testing.T, options *RunTestOptions) {
	statusCode, body := http_helper.HttpGet(t, urlWithBasicAuth(options, "images/"), &tls.Config{})

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

func urlWithoutAuth(options *RunTestOptions, path string) string {
	ip := appIp(options)
	return fmt.Sprintf("http://%s/%s", ip, path)
}

func urlWithBasicAuth(options *RunTestOptions, path string) string {
	ip := appIp(options)
	return fmt.Sprintf("http://foo:bar@%s/%s", ip, path)
}

func appIp(options *RunTestOptions) string {
	ip, ok := options.EnvVars["APP_IP"]

	if !ok {
		return "10.100.0.2"
	}

	return ip
}
