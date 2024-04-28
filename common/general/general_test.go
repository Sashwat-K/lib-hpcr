package general

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	cert "github.com/Sashwat-K/hpcr-encryption-certificate"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

const (
	simpleContractPath     = "../../samples/simple_contract.yaml"
	certificateDownloadUrl = "https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-15-encrypt.crt"

	sampleBase64Data        = "c2FzaHdhdGs="
	sampleDecodedBase64Data = "sashwatk"

	sampleCertificateJson = `{
		"1.0.0": "data1",
		"1.2.5": "data2",
		"2.0.5": "data3",
		"3.5.10": "data4",
		"4.0.0": "data5"
	}`

	sampleComposeFolder = "../../samples/tgz"
)

// Testcase to check ExecCommand() works
func TestExecCommand(t *testing.T) {
	_, err := ExecCommand("openssl", "", "version")

	assert.NoError(t, err)
}

// Testcase to check ExecCommand() when user input is given
func TestExecCommandUserInput(t *testing.T) {
	_, err := ExecCommand("openssl", "hello", "version")

	assert.NoError(t, err)
}

// Testcase to check if CreateTempFile() can create and modify temp files
func TestCreateTempFile(t *testing.T) {
	text := "Testing"
	tmpfile, err := CreateTempFile(text)

	file, err1 := os.Open(tmpfile)
	if err1 != nil {
		fmt.Println(err1)
	}
	defer file.Close()

	content, err1 := io.ReadAll(file)
	if err1 != nil {
		fmt.Println(err1)
	}

	err1 = os.Remove(tmpfile)
	if err1 != nil {
		fmt.Println(err1)
	}

	assert.Equal(t, text, string(content))
	assert.NoError(t, err)
}

// Testcase to check TestRemoveTempFile() removes a file
func TestRemoveTempFile(t *testing.T) {
	text := "Testing"
	tmpfile, err := CreateTempFile(text)
	if err != nil {
		fmt.Println(err)
	}

	err = RemoveTempFile(tmpfile)

	err1 := CheckFileFolderExists(tmpfile)

	assert.NoError(t, err)
	assert.False(t, err1, "The created file was removed and must not exist")
}

// Testcase to check if ListFoldersAndFiles() is able to list files and folders under a folder
func TestListFoldersAndFiles(t *testing.T) {
	result, err := ListFoldersAndFiles(sampleComposeFolder)
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, filepath.Join(sampleComposeFolder, "docker-compose.yaml"))
	assert.NoError(t, err)
}

// Testcase to check if CheckFileFolderExists() is able check if file or folder exists
func TestCheckFileFolderExists(t *testing.T) {
	result := CheckFileFolderExists(sampleComposeFolder)

	assert.True(t, result)
}

// Testcase to check if IsJSON() is able to check if input data is JSON or not
func TestIsJson(t *testing.T) {
	result := IsJSON(sampleCertificateJson)

	assert.Equal(t, result, true)
}

// Testcase to check if EncodeToBase64() can encode string to base64
func TestEncodeToBase64(t *testing.T) {
	result := EncodeToBase64(sampleDecodedBase64Data)

	assert.Equal(t, result, sampleBase64Data)
}

// Testcase to check if MapToYaml() can convert Map to YAML string
func TestMapToYaml(t *testing.T) {
	var contractMap map[string]interface{}

	file, err := os.Open(simpleContractPath)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	contract, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
	}

	err = yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		fmt.Println(err)
	}

	_, err = MapToYaml(contractMap["env"].(map[string]interface{}))
	if err != nil {
		fmt.Println(err)
	}

	assert.NoError(t, err)
}

// Testcase to check if KeyValueInjector() can add key value to existing map
func TestKeyValueInjector(t *testing.T) {
	var contractMap map[string]interface{}
	key := "envWorkloadSignature"
	value := "testing123"

	file, err := os.Open(simpleContractPath)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	contract, err := io.ReadAll(file)
	if err != nil {
		fmt.Println(err)
	}

	err = yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		fmt.Println(err)
	}

	finalContract, err := KeyValueInjector(contractMap, key, value)
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, finalContract, fmt.Sprintf("%s: %s", key, value))
	assert.NoError(t, err)
}

// Testcase to check if CertificateDownloader() can download encryption certificate
func TestCertificateDownloader(t *testing.T) {
	certificate, err := CertificateDownloader(certificateDownloadUrl)
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, certificate, "-----BEGIN CERTIFICATE-----")
	assert.NoError(t, err)
}

// Testcase to check if DecodeBase64String() can decode base64 string
func TestDecodeBase64String(t *testing.T) {
	result, err := DecodeBase64String(sampleBase64Data)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(result)

	assert.Equal(t, sampleDecodedBase64Data, result)
	assert.NoError(t, err)
}

// Testcase to check if GetEncryptPassWorkload() can fetch encoded encrypted password and encoded encrypted data from string
func TestGetEncryptPassWorkload(t *testing.T) {
	encryptedData := "hyper-protect-basic.sashwat.k"

	a, b := GetEncryptPassWorkload(encryptedData)

	assert.Equal(t, a, "sashwat")
	assert.Equal(t, b, "k")
}

func TestCheckUrlExists(t *testing.T) {
	result, err := CheckUrlExists(certificateDownloadUrl)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, result, true)
	assert.NoError(t, err)
}

func TestGetDataFromLatestVersion(t *testing.T) {
	versionConstraints := ">= 1.0.0, <= 3.5.10"

	key, value, err := GetDataFromLatestVersion(sampleCertificateJson, versionConstraints)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, key, "3.5.10")
	assert.Equal(t, value, "data4")
	assert.NoError(t, err)
}

// Testcase to check if FetchEncryptionCertificate() fetches encryption certificate
func TestFetchEncryptionCertificate(t *testing.T) {
	result := FetchEncryptionCertificate("")

	assert.Equal(t, result, cert.EncryptionCertificate)
}

// Testcase to check if TestGenerateTgzBase64() is able generate base64 of compose tgz
func TestGenerateTgzBase64(t *testing.T) {
	filesFoldersList, err := ListFoldersAndFiles(sampleComposeFolder)
	if err != nil {
		fmt.Println(err)
	}

	result, err := GenerateTgzBase64(filesFoldersList)
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, result)
	assert.NoError(t, err)
}
