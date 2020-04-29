package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
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
	Validators        map[string]func(*testing.T, *RunTestOptions)
	WaitForReady      func()
	EnvVars           map[string]string
}

func TestDockerfile(t *testing.T) {
	t.Parallel()

	options := &RunTestOptions{
		DockerComposeFile: "docker-compose.yaml",
		Validators: map[string]func(*testing.T, *RunTestOptions){
			"ValidateServerHeader":     validateServerHeader,
			"ValidatePhpHardening":     validatePhpHardeningConfigApplied,
			"ValidateDirectoryListing": validateDirectoryListingDenied,
			"ValidateIndexOk":          validateIndexOk,
		},
		WaitForReady: func() { time.Sleep(10 * time.Second) },
		EnvVars: map[string]string{
			"HTTP_PORT": "8180",
		},
	}

	runTestsWithDockerComposeFile(t, options)
}

func TestHtpasswdAuth(t *testing.T) {
	t.Parallel()

	options := &RunTestOptions{
		DockerComposeFile: "docker-compose.htpasswd.yaml",
		Validators: map[string]func(*testing.T, *RunTestOptions){
			"ValidateRequiresAuth":                validateRequiresAuth,
			"ValidateUnauthPageExcludesSignature": validateUnauthorizedPageExcludesSignature,
			"ValidateIndexOkHtPasswdAuth":         validateIndexOkHtpasswdAuth,
		},
		WaitForReady: func() { time.Sleep(10 * time.Second) },
		EnvVars: map[string]string{
			"HTTP_PORT": "8280",
		},
	}

	runTestsWithDockerComposeFile(t, options)
}

func TestOpenIDAuth(t *testing.T) {
	t.Parallel()

	options := &RunTestOptions{
		DockerComposeFile: "docker-compose.openid.yaml",
		Validators: map[string]func(*testing.T, *RunTestOptions){
			"ValidateRequiresOpenIDAuth":       validateRequiresOpenIDAuth,
			"ValidateLoggedOutDoesNotNeedAuth": validateLoggedOutDoesNotNeedAuth,
		},
		WaitForReady: func() { time.Sleep(10 * time.Second) },
		EnvVars: map[string]string{
			"HTTP_PORT": "8380",
		},
	}

	runTestsWithDockerComposeFile(t, options)
}

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

		options.WaitForReady()
	})

	test_structure.RunTestStage(t, "validate", func() {
		for name, validator := range options.Validators {
			t.Run(name, func(t *testing.T) {
				validator(t, options)
			})
		}
	})
}

func validateRequiresAuth(t *testing.T, options *RunTestOptions) {
	statusCode, body := http_helper.HttpGet(t, urlWithoutAuth(options, "index.php"), &tls.Config{})

	assert.Equal(t, 401, statusCode)
	assert.Contains(t, body, "Unauthorized")
}

func validateRequiresOpenIDAuth(t *testing.T, options *RunTestOptions) {
	url := urlWithoutAuth(options, "index.php")

	openIDHelper := OpenIDHelper{
		ProtectedUrl: url,
	}

	resp, err := openIDHelper.InitiateAuthFlow()
	if err != nil {
		t.Fatalf("Failed to initiate openid auth flow: %s", err)
		return
	}

	fmt.Println(string(resp.Body))

	assert.Equal(t, 302, resp.StatusCode, "Not redriected when trying to visit a protected url")
	assert.Equal(t, 1, len(resp.Headers["Location"]), "Wrong number of Location headers returned")
	assert.True(t,
		strings.HasPrefix(
			resp.Headers["Location"][0],
			fmt.Sprintf("http://%s/auth/realms/localrealm/protocol/openid-connect/auth?", keycloakHost(options)),
		),
		"Not redirected to the correct location when trying to visit a protected url unauthenticated",
	)
}

func validateLoggedOutDoesNotNeedAuth(t *testing.T, options *RunTestOptions) {
	statusCode, body := http_helper.HttpGet(t, urlWithoutAuth(options, "loggedout.php"), &tls.Config{})

	assert.Equal(t, 200, statusCode)
	assert.Contains(t, body, "Logged out")
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

func validateServerHeader(t *testing.T, options *RunTestOptions) {
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
	host := appHost(options)
	return fmt.Sprintf("http://%s/%s", host, path)
}

func urlWithBasicAuth(options *RunTestOptions, path string) string {
	host := appHost(options)
	return fmt.Sprintf("http://foo:bar@%s/%s", host, path)
}

func appHost(options *RunTestOptions) string {
	port, ok := options.EnvVars["HTTP_PORT"]

	if !ok {
		port = "80"
	}

	return fmt.Sprintf("127.0.0.1:%s", port)
}

func keycloakHost(options *RunTestOptions) string {
	port, ok := options.EnvVars["KEYCLOAK_PORT"]

	if !ok {
		port = "8080"
	}

	return fmt.Sprintf("127.0.0.1:%s", port)
}
