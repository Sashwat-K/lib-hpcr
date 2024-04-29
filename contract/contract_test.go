package contract

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
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

// Testcase to check if TestHpcrEncryptedtext() is able to encrypt text
func TestHpcrEncryptedtext(t *testing.T) {
	result, err := HpcrEncryptedtext(sampleStringData, "")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "hyper-protect-basic.")
}

// Testcase to check if TestHpcrEncryptedJson() is able to encrypt JSON
func TestHpcrEncryptedJson(t *testing.T) {
	result, err := HpcrEncryptedJson(sampleStringJson, "")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "hyper-protect-basic.")
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

func TestEncrypter(t *testing.T) {
	result, err := Encrypter(sampleStringJson, "")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "hyper-protect-basic.")
}
