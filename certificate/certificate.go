package certificate

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	gen "github.com/Sashwat-K/lib-hpcr/common/general"
)

const (
	defaultEncCertUrlTemplate = "https://cloud.ibm.com/media/docs/downloads/hyper-protect-container-runtime/ibm-hyper-protect-container-runtime-{{.Major}}-{{.Minor}}-s390x-{{.Patch}}-encrypt.crt"
)

type CertSpec struct {
	Major string
	Minor string
	Patch string
}

// GetEncryptionCertificateFromJson - function to get encryption certificate from encryption certificate JSON data
func GetEncryptionCertificateFromJson(encryptionCertificateJson, version string) (string, string, error) {
	return gen.GetDataFromLatestVersion(encryptionCertificateJson, version)
}

// DownloadEncryptionCertificates - function to download encryption certificates for specified versions
func DownloadEncryptionCertificates(versionList []string) (string, error) {
	var verCertMap = make(map[string]string)

	for _, version := range versionList {
		verSpec := strings.Split(version, ".")

		urlTemplate := template.New("url")
		urlTemplate, err := urlTemplate.Parse(defaultEncCertUrlTemplate)
		if err != nil {
			return "", err
		}

		builder := &strings.Builder{}
		err = urlTemplate.Execute(builder, CertSpec{verSpec[0], verSpec[1], verSpec[2]})
		if err != nil {
			return "", err
		}

		url := builder.String()
		status, err := gen.CheckUrlExists(url)
		if err != nil {
			return "", err
		}
		if !status {
			return "", fmt.Errorf("encryption certificate doesn't exist in %s", url)
		}

		cert, err := gen.CertificateDownloader(url)
		if err != nil {
			return "", err
		}

		verCertMap[version] = cert
	}

	jsonBytes, err := json.Marshal(verCertMap)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
