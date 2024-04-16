package general

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
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

// CreateTempFile - function to create temp file
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

// RemoveTempFile - function to remove temp file
func RemoveTempFile(filePath string) error {
	return os.Remove(filePath)
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

// DecodeBase64String - function to decode base64 string
func DecodeBase64String(base64Data string) (string, error) {
	decodedData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return "", err
	}

	return string(decodedData), nil
}

// GetEncryptPassWorkload - function to get encrypted password and encrypted workload from data
func GetEncryptPassWorkload(encryptedData string) (string, string) {
	return strings.Split(encryptedData, ".")[1], strings.Split(encryptedData, ".")[2]
}

// CheckUrlExists - function to check if URL exists or not
func CheckUrlExists(url string) (bool, error) {
	response, err := http.Head(url)
	if err != nil {
		return false, err
	}

	return response.StatusCode >= 200 && response.StatusCode < 300, nil
}

// GetDataFromLatestVersion - function to get the value based on constraints
func GetDataFromLatestVersion(jsonData, version string) (string, string, error) {
	var dataMap map[string]string
	if err := json.Unmarshal([]byte(jsonData), &dataMap); err != nil {
		return "", "", fmt.Errorf("error unmarshaling JSON data: %v", err)
	}

	targetConstraint, err := semver.NewConstraint(version)
	if err != nil {
		return "", "", fmt.Errorf("error parsing target version constraint: %v", err)
	}

	var matchingVersions []*semver.Version

	for versionStr := range dataMap {
		version, err := semver.NewVersion(versionStr)
		if err != nil {
			return "", "", fmt.Errorf("error parsing version: %v", err)
		}

		if targetConstraint.Check(version) {
			matchingVersions = append(matchingVersions, version)
		}
	}

	sort.Sort(sort.Reverse(semver.Collection(matchingVersions)))

	// Get the latest version and its corresponding data
	if len(matchingVersions) > 0 {
		latestVersion := matchingVersions[0]
		return latestVersion.String(), dataMap[latestVersion.String()], nil
	}

	// No matching version found
	return "", "", fmt.Errorf("no matching version found for the given constraint")
}
