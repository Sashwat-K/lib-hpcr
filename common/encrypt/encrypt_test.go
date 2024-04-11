package encrypt

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"

	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

const (
	certificateUrl       = "https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-1-0-s390x-15-encrypt.crt"
	simpleContractPath   = "../../samples/simple_contract.yaml"
	samplePrivateKeyPath = "../../samples/contract-expiry/private.pem"
	samplelCaCertPath    = "../../samples/contract-expiry/personal_ca.crt"
	sampleCaKeyPath      = "../../samples/contract-expiry/personal_ca.pem"
	sampleCsrFilePath    = "../../samples/contract-expiry/csr.pem"
)

func TestOpensslCheck(t *testing.T) {
	err := OpensslCheck()

	assert.NoError(t, err)
}

func TestRandomPasswordGenerator(t *testing.T) {
	result, err := RandomPasswordGenerator()

	assert.NotEmpty(t, result, "Random password did not get generated")
	assert.NoError(t, err)
}

func TestEncryptPassword(t *testing.T) {
	passowrd, err := RandomPasswordGenerator()
	if err != nil {
		fmt.Println(err)
	}

	encryptCertificate, err := gen.CertificateDownloader(certificateUrl)
	if err != nil {
		fmt.Println(err)
	}

	result, err := EncryptPassword(passowrd, encryptCertificate)
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, result, "Encrypted password did not get generated")
	assert.NoError(t, err)
}

func TestEncryptContract(t *testing.T) {
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

	passowrd, err := RandomPasswordGenerator()
	if err != nil {
		fmt.Println(err)
	}

	result, err := EncryptContract(passowrd, contractMap["workload"].(map[string]interface{}))
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, result, "Encrypted workload did not get generated")
	assert.NoError(t, err)
}

func TestEncryptFinalStr(t *testing.T) {
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

	password, err := RandomPasswordGenerator()
	if err != nil {
		fmt.Println(err)
	}

	encryptCertificate, err := gen.CertificateDownloader(certificateUrl)
	if err != nil {
		fmt.Println(err)
	}

	encryptedRandomPassword, err := EncryptPassword(password, encryptCertificate)
	if err != nil {
		fmt.Println(err)
	}

	encryptedWorkload, err := EncryptContract(password, contractMap["workload"].(map[string]interface{}))
	if err != nil {
		fmt.Println(err)
	}

	finalWorkload := EncryptFinalStr(encryptedRandomPassword, encryptedWorkload)

	assert.NotEmpty(t, finalWorkload, "Final workload did not get generated")
	assert.Contains(t, finalWorkload, "hyper-protect-basic.")
	assert.NoError(t, err)
}

func TestCreateSigningCert(t *testing.T) {
	privateKeyPath, err := os.Open(samplePrivateKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer privateKeyPath.Close()

	privateKey, err := io.ReadAll(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}

	cacertPath, err := os.Open(samplelCaCertPath)
	if err != nil {
		fmt.Println(err)
	}
	defer cacertPath.Close()

	cacert, err := io.ReadAll(cacertPath)
	if err != nil {
		fmt.Println(err)
	}

	caKeyPath, err := os.Open(sampleCaKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer caKeyPath.Close()

	caKey, err := io.ReadAll(caKeyPath)
	if err != nil {
		fmt.Println(err)
	}

	csrDataMap := map[string]interface{}{
		"country":  "IN",
		"state":    "Karnataka",
		"location": "Bangalore",
		"org":      "IBM",
		"unit":     "ISDL",
		"domain":   "HPVS",
		"mail":     "sashwat.k@ibm.com",
	}
	csrDataStr, err := json.Marshal(csrDataMap)
	if err != nil {
		fmt.Println(err)
	}

	signingCert, err := CreateSigningCert(string(privateKey), string(cacert), string(caKey), string(csrDataStr), "", 365)
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, signingCert, "Signing certificate did not get generated")
	assert.NoError(t, err)
}

func TestCreateSigningCertCsrFile(t *testing.T) {
	privateKeyPath, err := os.Open(samplePrivateKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer privateKeyPath.Close()

	privateKey, err := io.ReadAll(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}

	cacertPath, err := os.Open(samplelCaCertPath)
	if err != nil {
		fmt.Println(err)
	}
	defer cacertPath.Close()

	cacert, err := io.ReadAll(cacertPath)
	if err != nil {
		fmt.Println(err)
	}

	caKeyPath, err := os.Open(sampleCaKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer caKeyPath.Close()

	caKey, err := io.ReadAll(caKeyPath)
	if err != nil {
		fmt.Println(err)
	}

	csrFilePath, err := os.Open(sampleCsrFilePath)
	if err != nil {
		fmt.Println(err)
	}
	defer csrFilePath.Close()

	csr, err := io.ReadAll(csrFilePath)
	if err != nil {
		fmt.Println(err)
	}

	signingCert, err := CreateSigningCert(string(privateKey), string(cacert), string(caKey), "", string(csr), 365)
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, signingCert, "Signing certificate did not get generated")
	assert.NoError(t, err)
}

func TestSignContract(t *testing.T) {
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

	privateKeyPath, err := os.Open(samplePrivateKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer privateKeyPath.Close()

	privateKey, err := io.ReadAll(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}

	err = yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		fmt.Println(err)
	}

	password, err := RandomPasswordGenerator()
	if err != nil {
		fmt.Println(err)
	}

	encryptCertificate, err := gen.CertificateDownloader(certificateUrl)
	if err != nil {
		fmt.Println(err)
	}

	encryptedPassword, err := EncryptPassword(password, encryptCertificate)
	if err != nil {
		fmt.Println(err)
	}

	encryptedWorkload, err := EncryptContract(password, contractMap["workload"].(map[string]interface{}))
	if err != nil {
		fmt.Println(err)
	}
	finalWorkload := EncryptFinalStr(encryptedPassword, encryptedWorkload)

	encryptedEnv, err := EncryptContract(password, contractMap["env"].(map[string]interface{}))
	if err != nil {
		fmt.Println(err)
	}

	finalEnv := EncryptFinalStr(encryptedPassword, encryptedEnv)

	workloadEnvSignature, err := SignContract(finalWorkload, finalEnv, string(privateKey))
	if err != nil {
		fmt.Println(err)
	}

	assert.NotEmpty(t, workloadEnvSignature, "workloadEnvSignature did not get generated")
	assert.NoError(t, err)
}

func TestGenFinalSignedContract(t *testing.T) {
	_, err := GenFinalSignedContract("test1", "test2", "test3")

	assert.NoError(t, err)
}
