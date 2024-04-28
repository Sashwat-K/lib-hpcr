package contract

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	sampleBase64Data        = "c2FzaHdhdGs="
	sampleDecodedBase64Data = "sashwatk"
	sampleBase64Json        = "Cgl7CgkJInR5cGUiOiAiZW52IgoJfQoJ"
	sampleDecodedBase64Json = `
	{
		"type": "env"
	}
	`
	sampleComposeFolderPath = "../samples/tgz"
	composeTgzBase64        = "H4sIAAAAAAAA/9SSQU4DMQxFs+YUuUBbOySeyay4iuNxmagZBSWFqrdHBYS6ALGZDW/zZPkvbOnPVU7adlLXl9p1f+W1mK0BACDvb8YhwL0/cIgGPeEjEtHgDCB5JGNh80t+4LWfuRmAzn258Pn0W+6v/dcv3/4ndG1vWbRPD9YuWkrdXWor8220Nq/8rJP97Mg+10PJqXG7Hu6ST31hF2jyaR5GREwU0XOMc5JAoMQOlFMYjkeiEFjZ8wgSIIEEHzHSKEmc0jsAAAD//w=="
)

// Testcase to check if TestHpcrText() is able to encode text
func TestHpcrText(t *testing.T) {
	result, err := HpcrText(sampleDecodedBase64Data)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, result, sampleBase64Data)
}

// Testcase to check if HpcrJson() is able to encode JSON
func TestHpcrJson(t *testing.T) {
	result, err := HpcrJson(sampleDecodedBase64Json)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, result, sampleBase64Json)
}

// Testcase to check if TestHpcrEncryptedtext() is able to encrypt text
func TestHpcrEncryptedtext(t *testing.T) {
	result, err := HpcrEncryptedtext(sampleDecodedBase64Data, "")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "hyper-protect-basic.")
}

// Testcase to check if TestHpcrEncryptedJson() is able to encrypt JSON
func TestHpcrEncryptedJson(t *testing.T) {
	result, err := HpcrEncryptedJson(sampleDecodedBase64Json, "")
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

	assert.Equal(t, result, composeTgzBase64)
	assert.NoError(t, err)
}

func TestEncrypter(t *testing.T) {
	result, err := Encrypter(sampleDecodedBase64Json, "")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "hyper-protect-basic.")
}
