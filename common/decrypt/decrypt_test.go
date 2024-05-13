package decrypt

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

const (
	encryptedChecksumPath = "../../samples/attestation/se-checksums.txt.enc"
	privateKeyPath        = "../../samples/attestation/private.pem"
)

// Testcase to check if DecryptPassword() is able to decrypt password
func TestDecryptPassword(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		fmt.Println(err)
	}

	encodedEncryptedData := strings.Split(encChecksum, ".")[1]

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}

	_, err = DecryptPassword(encodedEncryptedData, privateKeyData)
	if err != nil {
		fmt.Println(err)
	}

	assert.NoError(t, err)
}

// Testcase to check if DecryptWorkload() is able to decrypt workload
func TestDecryptWorkload(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		fmt.Println(err)
	}

	encodedEncryptedPassword := strings.Split(encChecksum, ".")[1]
	encodedEncryptedData := strings.Split(encChecksum, ".")[2]

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}

	password, err := DecryptPassword(encodedEncryptedPassword, privateKeyData)
	if err != nil {
		fmt.Println(err)
	}

	result, err := DecryptWorkload(password, encodedEncryptedData)

	assert.Contains(t, result, "baseimage")
	assert.NoError(t, err)
}
