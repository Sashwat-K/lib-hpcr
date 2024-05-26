package contract

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

const (
	hpcrEncryptPrefix = "hyper-protect-basic."

	sampleStringData     = "sashwatk"
	sampleBase64Data     = "c2FzaHdhdGs="
	sampleInputChecksum  = "05fb716cba07a0cdda231f1aa19621ce9e183a4fb6e650b459bc3c5db7593e42"
	sampleOutputChecksum = "5fc9d046c6bb76741f2bd3029225955903727460c1da088bf9f0d93d17eaec69"

	sampleStringJson = `
	{
		"type": "env"
	}
	`
	sampleBase64Json         = "Cgl7CgkJInR5cGUiOiAiZW52IgoJfQoJ"
	sampleInputChecksumJson  = "f932f8ad556280f232f4b42d55b24ce7d2e909d3195ef60d49e92d49b735de2b"
	sampleOutputChecksumJson = "0e282874a193587be1d2aca98083e9ebbddc840edc964a130a215bd674f8487e"

	sampleComposeFolderPath     = "../samples/tgz"
	sampleComposeFolderChecksum = "3e4a006b9422a3fbf8c58d4f1dbac4494b34f800ddbb6e048c31709bb0cde599"
	sampleFolderTgzChecksum     = "4fde7c46fdc83340ea93d7a0746e53e21711bf2ee3a99669b55f5e469a89b1c1"

	simpleContractPath          = "../samples/simple_contract.yaml"
	simpleContractInputChecksum = "072cd6d89d9d253a0426eadea7217aedfe86197bfb8a5b4873386fcaa72ddfda"

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
	contract, err := gen.ReadDataFromFile(simpleContractPath)
	if err != nil {
		return "", "", "", "", "", err
	}

	privateKey, err := gen.ReadDataFromFile(samplePrivateKeyPath)
	if err != nil {
		return "", "", "", "", "", err
	}

	if testType == "TestHpcrContractSignedEncrypted" {
		return contract, privateKey, "", "", "", nil
	} else if testType == "TestEncryptWrapper" {
		publicKey, err := gen.ReadDataFromFile(samplePublicKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		return contract, privateKey, publicKey, "", "", nil
	} else if testType == "TestHpcrContractSignedEncryptedContractExpiryCsrParams" || testType == "TestHpcrContractSignedEncryptedContractExpiryCsrPem" {
		cePrivateKey, err := gen.ReadDataFromFile(sampleCePrivateKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		caCert, err := gen.ReadDataFromFile(sampleCeCaCertPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		caKey, err := gen.ReadDataFromFile(sampleCeCaKeyPath)
		if err != nil {
			return "", "", "", "", "", err
		}

		return contract, cePrivateKey, "", caCert, caKey, err
	}
	return "", "", "", "", "", err
}

// Testcase to check if TestHpcrText() is able to encode text and generate SHA256
func TestHpcrText(t *testing.T) {
	base64, inputSha256, outputSha256, err := HpcrText(sampleStringData)
	if err != nil {
		t.Errorf("failed to generate HPCR text - %v", err)
	}

	assert.Equal(t, base64, sampleBase64Data)
	assert.Equal(t, inputSha256, sampleInputChecksum)
	assert.Equal(t, outputSha256, sampleOutputChecksum)
}

// Testcase to check if HpcrJson() is able to encode JSON and generate SHA256
func TestHpcrJson(t *testing.T) {
	base64, inputSha256, outputSha256, err := HpcrJson(sampleStringJson)
	if err != nil {
		t.Errorf("failed to generate HPCR JSON - %v", err)
	}

	assert.Equal(t, base64, sampleBase64Json)
	assert.Equal(t, inputSha256, sampleInputChecksumJson)
	assert.Equal(t, outputSha256, sampleOutputChecksumJson)
}

// Testcase to check if TestHpcrTextEncrypted() is able to encrypt text and generate SHA256
func TestHpcrTextEncrypted(t *testing.T) {
	result, inputSha256, _, err := HpcrTextEncrypted(sampleStringData, "")
	if err != nil {
		t.Errorf("failed to generate HPCR encrypted text - %v", err)
	}

	assert.Contains(t, result, hpcrEncryptPrefix)
	assert.Equal(t, inputSha256, sampleInputChecksum)
}

// Testcase to check if TestHpcrJsonEncrypted() is able to encrypt JSON and generate SHA256
func TestHpcrJsonEncrypted(t *testing.T) {
	result, inputSha256, _, err := HpcrJsonEncrypted(sampleStringJson, "")
	if err != nil {
		t.Errorf("failed to generate HPCR encrypted JSON - %v", err)
	}

	assert.Contains(t, result, hpcrEncryptPrefix)
	assert.Equal(t, inputSha256, sampleInputChecksumJson)
}

// Testcase to check if HpcrTgz() is able to generate base64 of tar.tgz
func TestHpcrTgz(t *testing.T) {
	result, inputSha256, outputSha256, err := HpcrTgz(sampleComposeFolderPath)
	if err != nil {
		t.Errorf("failed to generate HPCR TGZ - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Equal(t, inputSha256, sampleComposeFolderChecksum)
	assert.Equal(t, outputSha256, sampleFolderTgzChecksum)
}

func TestHpcrTgzEncrypted(t *testing.T) {
	result, inputSha256, _, err := HpcrTgzEncrypted(sampleComposeFolderPath, "")
	if err != nil {
		t.Errorf("failed to generated HPCR encrypted TGZ - %v", err)
	}

	assert.Contains(t, result, hpcrEncryptPrefix)
	assert.Equal(t, inputSha256, sampleComposeFolderChecksum)
}

// Testcase to check if HpcrContractSignedEncrypted() is able to generate
func TestHpcrContractSignedEncrypted(t *testing.T) {

	contract, privateKey, _, _, _, err := common(t.Name())
	if err != nil {
		t.Errorf("failed to get contract and private key - %v", err)
	}

	result, inputSha256, _, err := HpcrContractSignedEncrypted(contract, "", privateKey)
	if err != nil {
		t.Errorf("failed to generate signed and encrypted contract - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Equal(t, inputSha256, simpleContractInputChecksum)
}

// Testcase to check if HpcrContractSignedEncryptedContractExpiry() is able to create signed and encrypted contract with contract expiry enabled with CSR parameters
func TestHpcrContractSignedEncryptedContractExpiryCsrParams(t *testing.T) {
	contract, privateKey, _, caCert, caKey, err := common(t.Name())
	if err != nil {
		t.Errorf("failed to get contract, private key, CA certificate and CA key - %v", err)
	}

	csrParams, err := json.Marshal(sampleCeCSRPems)
	if err != nil {
		t.Errorf("failed to unmarshal CSR parameters - %v", err)
	}

	result, inputSha256, _, err := HpcrContractSignedEncryptedContractExpiry(contract, "", privateKey, caCert, caKey, string(csrParams), "", sampleContractExpiryDays)
	if err != nil {
		t.Errorf("failed to generate signed and encrypted contract with contract expiry - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Equal(t, inputSha256, simpleContractInputChecksum)
}

// Testcase to check if HpcrContractSignedEncryptedContractExpiry() is able to create signed and encrypted contract with contract expiry enabled with CSR PEM data
func TestHpcrContractSignedEncryptedContractExpiryCsrPem(t *testing.T) {
	contract, privateKey, _, caCert, caKey, err := common(t.Name())
	if err != nil {
		t.Errorf("failed to get contract, private key, CA certificate and CA key - %v", err)
	}

	csr, err := gen.ReadDataFromFile(sampleCeCsrPath)
	if err != nil {
		t.Errorf("failed to read CSR file - %v", err)
	}

	result, inputSha256, _, err := HpcrContractSignedEncryptedContractExpiry(contract, "", privateKey, caCert, caKey, "", csr, sampleContractExpiryDays)
	if err != nil {
		t.Errorf("failed to generate signed and encrypted contract with contract expiry - %v", err)
	}

	assert.NotEmpty(t, result)
	assert.Equal(t, inputSha256, simpleContractInputChecksum)
}

// Testcase to check if EncryptWrapper() is able to sign and encrypt a contract
func TestEncryptWrapper(t *testing.T) {
	contract, privateKey, publicKey, _, _, err := common("TestEncryptWrapper")
	if err != nil {
		t.Errorf("failed to get contract, private key and public key - %v", err)
	}

	result, err := EncryptWrapper(contract, "", privateKey, publicKey)
	if err != nil {
		t.Errorf("failed to sign and encrypt contract - %v", err)
	}

	assert.NotEmpty(t, result)
}

// Testcase to check if Encrypter() is able to encrypt and generate SHA256 from string
func TestEncrypter(t *testing.T) {
	result, err := Encrypter(sampleStringJson, "")
	if err != nil {
		t.Errorf("failed to encrypt contract - %v", err)
	}

	assert.Contains(t, result, hpcrEncryptPrefix)
}
