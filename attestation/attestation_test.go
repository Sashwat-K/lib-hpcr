package attestation

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

const (
	encryptedChecksumPath = "../samples/attestation/se-checksums.txt.enc"
	privateKeyPath        = "../samples/attestation/private.pem"
)

// Testcase to check if HpcrGetAttestationRecords() retrieves attestation records from encrypted data
func TestHpcrGetAttestationRecords(t *testing.T) {
	encChecksum, err := gen.ReadDataFromFile(encryptedChecksumPath)
	if err != nil {
		fmt.Println(err)
	}

	privateKeyData, err := gen.ReadDataFromFile(privateKeyPath)
	if err != nil {
		fmt.Println(err)
	}

	result, err := HpcrGetAttestationRecords(encChecksum, privateKeyData)
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, result, "baseimage")
	assert.NoError(t, err)
}
