package contract

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

const (
	sampleStringData   = "sashwatk"
	sampleBase64Data   = "c2FzaHdhdGs="
	sampleDataChecksum = "05fb716cba07a0cdda231f1aa19621ce9e183a4fb6e650b459bc3c5db7593e42"

	sampleStringJson = `
	{
		"type": "env"
	}
	`
	sampleBase64Json   = "Cgl7CgkJInR5cGUiOiAiZW52IgoJfQoJ"
	sampleChecksumJson = "f932f8ad556280f232f4b42d55b24ce7d2e909d3195ef60d49e92d49b735de2b"

	sampleComposeFolderPath = "../samples/tgz"
	simpleContractPath      = "../samples/simple_contract.yaml"

	samplePrivateKeyPath = "../samples/encrypt/private.pem"
)

// Testcase to check if TestHpcrText() is able to encode text and generate SHA256
func TestHpcrText(t *testing.T) {
	base64, sha256, err := HpcrText(sampleStringData)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, base64, sampleBase64Data)
	assert.Equal(t, sha256, sampleDataChecksum)
}

// Testcase to check if HpcrJson() is able to encode JSON and generate SHA256
func TestHpcrJson(t *testing.T) {
	base64, sha256, err := HpcrJson(sampleStringJson)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, base64, sampleBase64Json)
	assert.Equal(t, sha256, sampleChecksumJson)
}

// Testcase to check if TestHpcrEncryptedtext() is able to encrypt text and generate SHA256
func TestHpcrEncryptedtext(t *testing.T) {
	result, sha256, err := HpcrEncryptedtext(sampleStringData, "")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "hyper-protect-basic.")
	assert.Equal(t, sha256, sampleDataChecksum)
}

// Testcase to check if TestHpcrEncryptedJson() is able to encrypt JSON and generate SHA256
func TestHpcrEncryptedJson(t *testing.T) {
	result, sha256, err := HpcrEncryptedJson(sampleStringJson, "")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "hyper-protect-basic.")
	assert.Equal(t, sha256, sampleChecksumJson)
}

// Testcase to check if HpcrTgz() is able to generate base64 of tar.tgz
func TestHpcrTgz(t *testing.T) {
	result, err := HpcrTgz(sampleComposeFolderPath)
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, result)
	assert.NoError(t, err)
}

// Testcase to check if HpcrContractSignedEncrypted() is able to generate
func TestHpcrContractSignedEncrypted(t *testing.T) {
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

	privateKeyFile, err := os.Open(samplePrivateKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer privateKeyFile.Close()

	privateKey, err := io.ReadAll(privateKeyFile)
	if err != nil {
		fmt.Println(err)
	}

	contractStr, err := gen.MapToYaml(contractMap)
	if err != nil {
		fmt.Println(err)
	}

	result, err := HpcrContractSignedEncrypted(contractStr, string(privateKey), "")
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, result)
	assert.NoError(t, err)
}

// Testcase to check if Encrypter() is able to encrypt and generate SHA256 from string
func TestEncrypter(t *testing.T) {
	result, sha256, err := Encrypter(sampleStringJson, "")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "hyper-protect-basic.")
	assert.Equal(t, sha256, sampleChecksumJson)
}
