package attestation

import (
	"fmt"

	attest "github.com/Sashwat-K/lib-hpcr/common/decrypt"
	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

const (
	missingParameterErrStatement = "required parameter missing"
)

// HpcrGetAttestationRecords - function to get attestation records from encrypted data
func HpcrGetAttestationRecords(data, privateKey string) (string, error) {
	if gen.CheckIfEmpty(data, privateKey) {
		return "", fmt.Errorf(missingParameterErrStatement)
	}
	encodedEncryptedPassword, encodedEncryptedData := gen.GetEncryptPassWorkload(data)

	password, err := attest.DecryptPassword(encodedEncryptedPassword, privateKey)
	if err != nil {
		return "", err
	}

	attestationRecords, err := attest.DecryptWorkload(password, encodedEncryptedData)
	if err != nil {
		return "", err
	}

	return attestationRecords, nil
}
