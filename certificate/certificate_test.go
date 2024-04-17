package certificate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEncryptionCertificateFromJson(t *testing.T) {
	jsonData := `{
		"1.0.0": "data1",
		"1.2.5": "data2",
		"2.0.5": "data3",
		"3.5.10": "data4",
		"4.0.0": "data5"
	}`
	version := "> 1.0.0"

	key, value, err := GetEncryptionCertificateFromJson(jsonData, version)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, key, "4.0.0")
	assert.Equal(t, value, "data5")
	assert.NoError(t, err)
}

func TestDownloadEncryptionCertificates(t *testing.T) {
	version := []string{"1.0.13", "1.0.14", "1.0.15"}
	certs, err := DownloadEncryptionCertificates(version)
	if err != nil {
		fmt.Println(err)
	}

	assert.Contains(t, certs, "1.0.13")
	assert.NoError(t, err)
}

func TestCombined(t *testing.T) {
	encryptionCertVersions := []string{"1.0.13", "1.0.14", "1.0.15"}
	certs, err := DownloadEncryptionCertificates(encryptionCertVersions)
	if err != nil {
		fmt.Println(err)
	}

	version := "> 1.0.14"

	key, _, err := GetEncryptionCertificateFromJson(certs, version)
	if err != nil {
		fmt.Println(err)
	}

	assert.Equal(t, key, "1.0.15")
	assert.NoError(t, err)
}
