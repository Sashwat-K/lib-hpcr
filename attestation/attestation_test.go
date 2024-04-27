package attestation

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	encryptedChecksumPath = "../samples/attestation/se-checksums.txt.enc"
	privateKeyPath        = "../samples/attestation/private.pem"
)

// Testcase to check if HpcrGetAttestationRecords() retrieves attestation records from encrypted data
func TestHpcrGetAttestationRecords(t *testing.T) {
	encChecksumPath, err := os.Open(encryptedChecksumPath)
	if err != nil {
		fmt.Println(err)
	}
	defer encChecksumPath.Close()

	encChecksum, err := io.ReadAll(encChecksumPath)
	if err != nil {
		fmt.Println(err)
	}

	privateKey, err := os.Open(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}
	defer privateKey.Close()

	privateKeyData, err := io.ReadAll(privateKey)
	if err != nil {
		fmt.Println(err)
	}

	result, err := HpcrGetAttestationRecords(string(encChecksum), string(privateKeyData))
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "baseimage")
	assert.NoError(t, err)
}
