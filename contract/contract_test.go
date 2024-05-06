package contract

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	simpleContractPath      = "../samples/simple_contract.yaml"

	samplePrivateKeyPath = "../samples/encrypt/private.pem"
	samplePublicKeyPath  = "../samples/encrypt/public.pem"

	sampleCePrivateKeyPath   = "../samples/contract-expiry/private.pem"
	sampleCeCaCertPath       = "../samples/contract-expiry/personal_ca.crt"
	sampleCeCaKeyPath        = "../samples/contract-expiry/personal_ca.pem"
	sampleCeCsrPath          = "../samples/contract-expiry/csr.pem"
	sampleContractExpiryDays = 365
)

var (
	sampleCeCSRPems = map[string]interface{}{
		"country":  "IN",
		"state":    "Karnataka",
		"location": "Bangalore",
		"org":      "IBM",
		"unit":     "ISDL",
		"domain":   "HPVS",
		"mail":     "sashwat.k@ibm.com",
	}
)

// common - common function to pull data from files
func common(testType string) (string, string, string, string, string, error) {
	simpleContractFile, err := os.Open(simpleContractPath)
	if err != nil {
		return "", "", "", "", "", err
	}
	defer simpleContractFile.Close()

	contract, err := io.ReadAll(simpleContractFile)
	if err != nil {
		return "", "", "", "", "", err
	}

	privateKeyFile, err := os.Open(samplePrivateKeyPath)
	if err != nil {
		return "", "", "", "", "", err
	}
	defer privateKeyFile.Close()

	privateKey, err := io.ReadAll(privateKeyFile)
	if err != nil {
		return "", "", "", "", "", err
	}

	if testType == "TestHpcrContractSignedEncrypted" {
		return string(contract), string(privateKey), "", "", "", nil
	} else if testType == "TestEncryptWrapper" {
		publicKeyFile, err := os.Open(samplePublicKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}
		defer privateKeyFile.Close()

		publicKey, err := io.ReadAll(publicKeyFile)
		if err != nil {
			return "", "", "", "", "", err
		}
		return string(contract), string(privateKey), string(publicKey), "", "", nil
	} else if testType == "TestHpcrContractSignedEncryptedContractExpiryCsrParams" || testType == "TestHpcrContractSignedEncryptedContractExpiryCsrPem" {
		cePrivateKeyPath, err := os.Open(sampleCePrivateKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}
		defer cePrivateKeyPath.Close()

		cePrivateKey, err := io.ReadAll(cePrivateKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		caCertPath, err := os.Open(sampleCeCaCertPath)
		if err != nil {
			fmt.Println("Error parsing CA certificate - ", err)
			return "", "", "", "", "", err
		}
		defer caCertPath.Close()

		caCert, err := io.ReadAll(caCertPath)
		if err != nil {
			fmt.Println(err)
			return "", "", "", "", "", err
		}

		caKeyPath, err := os.Open(sampleCeCaKeyPath)
		if err != nil {
			fmt.Println("Error parsing CA certificate - ", err)
			return "", "", "", "", "", err
		}
		defer caCertPath.Close()

		caKey, err := io.ReadAll(caKeyPath)
		if err != nil {
			fmt.Println(err)
			return "", "", "", "", "", err
		}

		return string(contract), string(cePrivateKey), "", string(caCert), string(caKey), err
	}
	return "", "", "", "", "", err
}

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

	contract, privateKey, _, _, _, err := common("TestHpcrContractSignedEncrypted")
	if err != nil {
		fmt.Println(err)
	}

	result, err := HpcrContractSignedEncrypted(contract, "", privateKey)
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, result)
	assert.NoError(t, err)
}

// Testcase to check if HpcrContractSignedEncryptedContractExpiry() is able to create signed and encrypted contract with contract expiry enabled with CSR parameters
func TestHpcrContractSignedEncryptedContractExpiryCsrParams(t *testing.T) {
	contract, privateKey, _, caCert, caKey, err := common("TestHpcrContractSignedEncryptedContractExpiryCsrParams")
	if err != nil {
		fmt.Println(err)
	}

	csrParams, err := json.Marshal(sampleCeCSRPems)
	if err != nil {
		fmt.Println(err)
	}

	result, err := HpcrContractSignedEncryptedContractExpiry(contract, "", privateKey, caCert, caKey, string(csrParams), "", sampleContractExpiryDays)
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, result)
	assert.NoError(t, err)
}

// Testcase to check if HpcrContractSignedEncryptedContractExpiry() is able to create signed and encrypted contract with contract expiry enabled with CSR PEM data
func TestHpcrContractSignedEncryptedContractExpiryCsrPem(t *testing.T) {
	contract, privateKey, _, caCert, caKey, err := common("TestHpcrContractSignedEncryptedContractExpiryCsrPem")
	if err != nil {
		fmt.Println(err)
	}

	csrPemFile, err := os.Open(sampleCeCsrPath)
	if err != nil {
		fmt.Println("Error parsing CSR - ", err)
	}
	defer csrPemFile.Close()

	csr, err := io.ReadAll(csrPemFile)
	if err != nil {
		fmt.Println(err)
	}

	result, err := HpcrContractSignedEncryptedContractExpiry(contract, "", privateKey, caCert, caKey, "", string(csr), sampleContractExpiryDays)
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, result)
	assert.NoError(t, err)
}

// Testcase to check if EncryptWrapper() is able to sign and encrypt a contract
func TestEncryptWrapper(t *testing.T) {
	contract, privateKey, publicKey, _, _, err := common("TestEncryptWrapper")
	if err != nil {
		fmt.Println(err)
	}

	result, err := EncryptWrapper(contract, "", privateKey, publicKey)
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
