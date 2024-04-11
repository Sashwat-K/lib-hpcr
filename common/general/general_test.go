package general

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

const (
	simpleContractPath = "../../samples/simple_contract.yaml"
)

func TestExecCommand(t *testing.T) {
	_, err := ExecCommand("openssl", "", "version")

	assert.NoError(t, err)
}

func TestExecCommandUserInput(t *testing.T) {
	_, err := ExecCommand("openssl", "hello", "version")

	assert.NoError(t, err)
}

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

func TestEncodeToBase64(t *testing.T) {
	base64data := "c2FzaHdhdGs="
	result := EncodeToBase64("sashwatk")

	assert.Equal(t, result, base64data)
}

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

func TestCertificateDownloader(t *testing.T) {
	certificate, err := CertificateDownloader("https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-15-encrypt.crt")
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, certificate, "-----BEGIN CERTIFICATE-----")
	assert.NoError(t, err)
}
