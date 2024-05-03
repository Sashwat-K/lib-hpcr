package contract

import (
	"fmt"

	enc "github.com/Sashwat-K/lib-hpcr/common/encrypt"
	gen "github.com/Sashwat-K/lib-hpcr/common/general"
	"gopkg.in/yaml.v3"
)

// HpcrText - function to generate base64 data and checksum from string
func HpcrText(plainText string) (string, string, error) {
	if plainText == "" {
		return "", "", fmt.Errorf("input is empty")
	}
	return gen.EncodeToBase64(plainText), gen.GenerateSha256(plainText), nil
}

// HpcrJson - function to generate base64 data and checksum from JSON string
func HpcrJson(plainJson string) (string, string, error) {
	if !gen.IsJSON(plainJson) {
		return "", "", fmt.Errorf("not a JSON data")
	}
	return gen.EncodeToBase64(plainJson), gen.GenerateSha256(plainJson), nil
}

// HpcrEncryptedtext - function to generate encrypted Hyper protect data and SHA256 from plain text
func HpcrEncryptedtext(plainText, encryptionCertificate string) (string, string, error) {
	if plainText == "" {
		return "", "", fmt.Errorf("input text is empty")
	}
	return Encrypter(plainText, encryptionCertificate)
}

// HpcrEncryptedJson - function to generate encrypted hyper protect data and SHA256 from plain JSON data
func HpcrEncryptedJson(plainJson, encryptionCertificate string) (string, string, error) {
	if !gen.IsJSON(plainJson) {
		return "", "", fmt.Errorf("contract is not a JSON data")
	}
	return Encrypter(plainJson, encryptionCertificate)
}

// HpcrTgz - function to generate base64 of tar.tgz which was prepared from docker compose/podman files
func HpcrTgz(folderPath string) (string, error) {
	if !gen.CheckFileFolderExists(folderPath) {
		return "", fmt.Errorf("folder doesn't exists - %s", folderPath)
	}

	filesFoldersList, err := gen.ListFoldersAndFiles(folderPath)
	if err != nil {
		return "", err
	}

	tgzBase64, err := gen.GenerateTgzBase64(filesFoldersList)
	if err != nil {
		return "", err
	}

	return tgzBase64, nil
}

// HpcrContractSignedEncrypted - function to generate Signed and Encrypted contract
func HpcrContractSignedEncrypted(contract, privateKey, encryptionCertificate string) (string, error) {
	var contractMap map[string]interface{}

	if contract == "" || privateKey == "" {
		return "", fmt.Errorf("either contract or private key not parsed")
	}

	encryptCertificate := gen.FetchEncryptionCertificate(encryptionCertificate)

	err := yaml.Unmarshal([]byte(contract), &contractMap)
	if err != nil {
		return "", err
	}

	workloadData, err := gen.MapToYaml(contractMap["workload"].(map[string]interface{}))
	if err != nil {
		return "", err
	}

	encryptedWorkload, _, err := Encrypter(workloadData, encryptCertificate)
	if err != nil {
		return "", err
	}

	publicKey, err := enc.GeneratePublicKey(privateKey)
	if err != nil {
		return "", err
	}

	updatedEnv, err := gen.KeyValueInjector(contractMap["env"].(map[string]interface{}), "signingKey", gen.EncodeToBase64(publicKey))
	if err != nil {
		return "", err
	}

	encryptedEnv, _, err := Encrypter(updatedEnv, encryptCertificate)
	if err != nil {
		return "", err
	}

	workloadEnvSignature, err := enc.SignContract(encryptedWorkload, encryptedEnv, privateKey)
	if err != nil {
		return "", err
	}

	finalContract, err := enc.GenFinalSignedContract(encryptedWorkload, encryptedEnv, workloadEnvSignature)
	if err != nil {
		return "", err
	}

	return finalContract, nil
}

// Encrypter - function to generate encrypted hyper protect data from plain string
func Encrypter(stringText, encryptionCertificate string) (string, string, error) {
	encCert := gen.FetchEncryptionCertificate(encryptionCertificate)

	password, err := enc.RandomPasswordGenerator()
	if err != nil {
		fmt.Println(err)
	}

	encodedEncryptedPassword, err := enc.EncryptPassword(password, encCert)
	if err != nil {
		fmt.Println(err)
	}

	encryptedString, err := enc.EncryptString(password, stringText)
	if err != nil {
		fmt.Println(err)
	}

	return enc.EncryptFinalStr(encodedEncryptedPassword, encryptedString), gen.GenerateSha256(stringText), nil
}
