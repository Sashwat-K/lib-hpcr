package contract

import (
	"fmt"

	enc "github.com/Sashwat-K/lib-hpcr/common/encrypt"
	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

// function to generate base64 data from string
func HpcrText(plainText string) (string, error) {
	if plainText == "" {
		return "", fmt.Errorf("input is empty")
	}
	return gen.EncodeToBase64(plainText), nil
}

// function to generate base64 data from JSON string
func HpcrJson(plainJson string) (string, error) {
	if !gen.IsJSON(plainJson) {
		return "", fmt.Errorf("not a JSON data")
	}
	return gen.EncodeToBase64(plainJson), nil
}

// function to generate encrypted Hyper protect data from plain text
func HpcrEncryptedtext(plainText, encryptionCertificate string) (string, error) {
	return Encrypter(plainText, encryptionCertificate)
}

// function to generate encrypted hyper protect data from plain JSON data
func HpcrEncryptedJson(plainJson, encryptionCertificate string) (string, error) {
	if !gen.IsJSON(plainJson) {
		return "", fmt.Errorf("contract is not a JSON data")
	}
	return Encrypter(plainJson, encryptionCertificate)
}

// function to generate encrypted hyper protect data from plain string
func Encrypter(stringText, encryptionCertificate string) (string, error) {
	encCert := gen.FetchEncryptionCertificate(encryptionCertificate)

	password, err := enc.RandomPasswordGenerator()
	if err != nil {
		fmt.Println(err)
	}

	encodedEncryptedPassowrd, err := enc.EncryptPassword(password, encCert)
	if err != nil {
		fmt.Println(err)
	}

	encryptedString, err := enc.EncryptString(password, stringText)
	if err != nil {
		fmt.Println(err)
	}

	return enc.EncryptFinalStr(encodedEncryptedPassowrd, encryptedString), nil
}

//
