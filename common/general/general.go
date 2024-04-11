package general

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// ExecCommand - function to run os commands
func ExecCommand(name string, stdinInput string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)

	// Check for standard input
	if stdinInput != "" {
		stdinPipe, err := cmd.StdinPipe()
		if err != nil {
			return "", err
		}
		defer stdinPipe.Close()

		go func() {
			defer stdinPipe.Close()
			stdinPipe.Write([]byte(stdinInput))
		}()
	}

	// Buffer to capture the output from the command.
	var out bytes.Buffer
	cmd.Stdout = &out

	// Run the command.
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Return the output from the command and nil for the error.
	return out.String(), nil
}

// CreateTempFile - Function to create temp file
func CreateTempFile(data string) (string, error) {

	trimmedData := strings.TrimSpace(data)
	tmpFile, err := os.CreateTemp("", "hpvs-")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Write the data to the temp file.
	_, err = tmpFile.WriteString(trimmedData)
	if err != nil {
		return "", err
	}

	// Return the path to the temp file.
	return tmpFile.Name(), nil
}

// EncodeToBase64 - function to encode string as base64
func EncodeToBase64(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

// MapToYaml - function to convert string map to YAML
func MapToYaml(m map[string]interface{}) (string, error) {
	// Marshal the map into a YAML string.
	yamlBytes, err := yaml.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(yamlBytes), nil
}

// KeyValueInjector - function to inject key value pair in YAML
func KeyValueInjector(contract map[string]interface{}, key, value string) (string, error) {
	contract[key] = value

	modifiedYAMLBytes, err := yaml.Marshal(contract)
	if err != nil {
		return "", err
	}

	return string(modifiedYAMLBytes), nil
}

// CertificateDownloader - function to download encryption certificate
func CertificateDownloader(url string) (string, error) {
	// Send a GET request to the URL
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
