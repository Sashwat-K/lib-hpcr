package decrypt

import (
	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

// DecryptPassword - function to decrypt encrypted string with private key
func DecryptPassword(base64EncryptedData, privateKey string) (string, error) {
	decodedEncryptedData, err := gen.DecodeBase64String(base64EncryptedData)
	if err != nil {
		return "", err
	}

	encryptedDataPath, err := gen.CreateTempFile(decodedEncryptedData)
	if err != nil {
		return "", err
	}

	privateKeyPath, err := gen.CreateTempFile(privateKey)
	if err != nil {
		return "", err
	}

	result, err := gen.ExecCommand("openssl", "", "pkeyutl", "-decrypt", "-inkey", privateKeyPath, "-in", encryptedDataPath)
	if err != nil {
		return "", err
	}

	for _, path := range []string{encryptedDataPath, privateKeyPath} {
		err := gen.RemoveTempFile(path)
		if err != nil {
			return "", err
		}
	}

	return result, nil
}

// DecryptWorkload - function to decrypt workload using password
func DecryptWorkload(password, encryptedWorkload string) (string, error) {
	decodedEncryptedWorkload, err := gen.DecodeBase64String(encryptedWorkload)
	if err != nil {
		return "", err
	}

	encryptedDataPath, err := gen.CreateTempFile(decodedEncryptedWorkload)
	if err != nil {
		return "", err
	}

	result, err := gen.ExecCommand("openssl", password, "aes-256-cbc", "-d", "-pbkdf2", "-in", encryptedDataPath, "-pass", "stdin")
	if err != nil {
		return "", err
	}

	err = gen.RemoveTempFile(encryptedDataPath)
	if err != nil {
		return "", err
	}

	return result, nil
}
