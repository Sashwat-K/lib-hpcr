package attestation

import (
	attest "github.com/Sashwat-K/lib-hpcr/common/decrypt"
	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

// HpcrGetAttestationRecords - function to get attestation records from encrypted data
func HpcrGetAttestationRecords(data, privateKey string) (string, error) {
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
