package encrypt

import (
	"encoding/json"
	"fmt"

	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

const (
	keylen = 32
)

// OpensslCheck - function to check if openssl exists
func OpensslCheck() error {
	_, err := gen.ExecCommand("openssl", "", "version")

	if err != nil {
		return err
	}

	return nil
}

// GeneratePublicKey - function to generate public key from private key
func GeneratePublicKey(privateKey string) (string, error) {
	privateKeyPath, err := gen.CreateTempFile(privateKey)
	if err != nil {
		return "", err
	}

	publicKey, err := gen.ExecCommand("openssl", "", "rsa", "-in", privateKeyPath, "-pubout")
	if err != nil {
		return "", err
	}

	return publicKey, nil
}

// RandomPasswordGenerator - function to generate random password
func RandomPasswordGenerator() (string, error) {
	randomPassword, err := gen.ExecCommand("openssl", "", "rand", fmt.Sprint(keylen))
	if err != nil {
		return "", err
	}

	return randomPassword, nil
}

// EncryptPassword - function to encrypt password
func EncryptPassword(password, cert string) (string, error) {
	encryptCertPath, err := gen.CreateTempFile(cert)
	if err != nil {
		return "", err
	}

	result, err := gen.ExecCommand("openssl", password, "rsautl", "-encrypt", "-inkey", encryptCertPath, "-certin")
	if err != nil {
		return "", err
	}

	err = gen.RemoveTempFile(encryptCertPath)
	if err != nil {
		return "", err
	}

	return gen.EncodeToBase64(result), nil
}

// EncryptContract - function to encrypt contract
func EncryptContract(password string, section map[string]interface{}) (string, error) {
	contract, err := gen.MapToYaml(section)
	if err != nil {
		return "", err
	}

	return EncryptString(password, contract)
}

// EncryptString - function to encrypt string
func EncryptString(password, section string) (string, error) {
	contractPath, err := gen.CreateTempFile(section)
	if err != nil {
		return "", err
	}

	result, err := gen.ExecCommand("openssl", password, "enc", "-aes-256-cbc", "-pbkdf2", "-pass", "stdin", "-in", contractPath)
	if err != nil {
		return "", err
	}

	err = gen.RemoveTempFile(contractPath)
	if err != nil {
		return "", err
	}

	return gen.EncodeToBase64(result), nil
}

// EncryptFinalStr - function to get final encrypted section
func EncryptFinalStr(encryptedPassword, encryptedContract string) string {
	return fmt.Sprintf("hyper-protect-basic.%s.%s", encryptedPassword, encryptedContract)
}

// CreateSigningCert - function to generate Signing Certificate
func CreateSigningCert(privateKey, cacert, cakey, csrData, csrPemData string, expiryDays int) (string, error) {
	var csr string
	if csrPemData == "" {
		privateKeyPath, err := gen.CreateTempFile(privateKey)
		if err != nil {
			return "", err
		}

		var csrDataMap map[string]interface{}
		err = json.Unmarshal([]byte(csrData), &csrDataMap)
		if err != nil {
			return "", err
		}

		csrParam := fmt.Sprintf("/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%sC/emailAddress=%s", csrDataMap["country"], csrDataMap["state"], csrDataMap["location"], csrDataMap["org"], csrDataMap["unit"], csrDataMap["domain"], csrDataMap["mail"])

		csr, err = gen.ExecCommand("openssl", "", "req", "-new", "-key", privateKeyPath, "-subj", csrParam)
		if err != nil {
			return "", err
		}

		err = gen.RemoveTempFile(privateKeyPath)
		if err != nil {
			return "", err
		}

	} else {
		csr = csrPemData
	}

	csrPath, err := gen.CreateTempFile(csr)
	if err != nil {
		return "", err
	}

	caCertPath, err := gen.CreateTempFile(cacert)
	if err != nil {
		return "", err
	}
	caKeyPath, err := gen.CreateTempFile(cakey)
	if err != nil {
		return "", err
	}

	signingCert, err := CreateCert(csrPath, caCertPath, caKeyPath, expiryDays)
	if err != nil {
		return "", err
	}

	for _, path := range []string{csrPath, caCertPath, caKeyPath} {
		err := gen.RemoveTempFile(path)
		if err != nil {
			return "", err
		}
	}

	return gen.EncodeToBase64(signingCert), nil
}

// CreateCert - function to create signing certificate
func CreateCert(csrPath, caCertPath, caKeyPath string, expiryDays int) (string, error) {
	signingCert, err := gen.ExecCommand("openssl", "", "x509", "-req", "-in", csrPath, "-CA", caCertPath, "-CAkey", caKeyPath, "-CAcreateserial", "-days", fmt.Sprintf("%d", expiryDays))
	if err != nil {
		return "", err
	}

	return signingCert, nil
}

// SignContract - function to sign encrypted contract
func SignContract(encryptedWorkload, encryptedEnv, privateKey string) (string, error) {
	combinedContract := encryptedWorkload + encryptedEnv

	privateKeyPath, err := gen.CreateTempFile(privateKey)
	if err != nil {
		return "", err
	}

	workloadEnvSignature, err := gen.ExecCommand("openssl", combinedContract, "dgst", "-sha256", "-sign", privateKeyPath)
	if err != nil {
		return "", err
	}

	err = gen.RemoveTempFile(privateKeyPath)
	if err != nil {
		return "", err
	}

	return gen.EncodeToBase64(workloadEnvSignature), nil
}

// GenFinalSignedContract - function to generate the final contract
func GenFinalSignedContract(workload, env, workloadEnvSig string) (string, error) {
	contract := map[string]interface{}{
		"workload":             workload,
		"env":                  env,
		"envWorkloadSignature": workloadEnvSig,
	}

	finalContract, err := gen.MapToYaml(contract)
	if err != nil {
		return "", err
	}

	return finalContract, nil
}
