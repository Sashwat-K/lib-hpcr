package decrypt

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	encryptedChecksumPath = "../../samples/attestation/se-checksums.txt.enc"
	privateKeyPath        = "../../samples/attestation/private.pem"
)

// Testcase to check if DecryptPassword() is able to decrypt password
func TestDecryptPassword(t *testing.T) {
	encChecksumPath, err := os.Open(encryptedChecksumPath)
	if err != nil {
		fmt.Println(err)
	}
	defer encChecksumPath.Close()

	encChecksum, err := io.ReadAll(encChecksumPath)
	if err != nil {
		fmt.Println(err)
	}

	encodedEncryptedData := strings.Split(string(encChecksum), ".")[1]

	privateKey, err := os.Open(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer privateKey.Close()

	privateKeyData, err := io.ReadAll(privateKey)
	if err != nil {
		fmt.Println(err)
	}

	_, err = DecryptPassword(encodedEncryptedData, string(privateKeyData))
	if err != nil {
		fmt.Println(err)
	}

	assert.NoError(t, err)
}

// Testcase to check if DecryptWorkload() is able to decrypt workload
func TestDecryptWorkload(t *testing.T) {
	encChecksumPath, err := os.Open(encryptedChecksumPath)
	if err != nil {
		fmt.Println(err)
	}
	defer encChecksumPath.Close()

	encChecksum, err := io.ReadAll(encChecksumPath)
	if err != nil {
		fmt.Println(err)
	}

	encodedEncryptedPassword := strings.Split(string(encChecksum), ".")[1]
	encodedEncryptedData := strings.Split(string(encChecksum), ".")[2]

	privateKey, err := os.Open(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer privateKey.Close()

	privateKeyData, err := io.ReadAll(privateKey)
	if err != nil {
		fmt.Println(err)
	}

	password, err := DecryptPassword(encodedEncryptedPassword, string(privateKeyData))
	if err != nil {
		fmt.Println(err)
	}

	result, err := DecryptWorkload(password, encodedEncryptedData)

	assert.Contains(t, result, "baseimage")
	assert.NoError(t, err)
}
