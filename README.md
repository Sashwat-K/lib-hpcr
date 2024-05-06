# lib-hpcr


## Introduction

The library has been developed to simply the process for provisioning HPVS on both IBM Cloud and On Prem.
For more details regarding HPVS, refer [Confidential computing with LinuxONE](https://cloud.ibm.com/docs/vpc?topic=vpc-about-se)


## Usage


### HpcrGetAttestationRecords()
This function decrypts encrypted attestation records.

```go
import "github.com/Sashwat-K/lib-hpcr/attestation"
```

#### Input(s)
1. Encrypted attestation records
2. Private key

#### Output(s)
1. Decrypted attestation records


### HpcrDownloadEncryptionCertificates()
This function downloads HPCR encryption certificates from IBM Cloud.

```go
import "github.com/Sashwat-K/lib-hpcr/certificate"
```

#### Input(s)
1. List of versions to download (eg: ["1.1.14", "1.1.15"])

#### Output(s)
1. Certificates and versions as JSON string


### HpcrGetEncryptionCertificateFromJson()
This function returns encryption certificate and version from HpcrDownloadEncryptionCertificates() output.

```go
import "github.com/Sashwat-K/lib-hpcr/certificate"
```

#### Input(s)
1. Encryption certificate JSON string
2. Version name

#### Output(s)
1. Version name
2. Encryption Certificate


### HpcrText()
This function generates Base64 for given string.

```go
import "github.com/Sashwat-K/lib-hpcr/contract"
```

#### Input(s)
1. Text to encode

#### Output(s)
1. Base64 of input
2. Checksum of input


### HpcrTextEncrypted()
This function encrypts text and formats text as per `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

```go
import "github.com/Sashwat-K/lib-hpcr/contract"
```

#### Input(s)
1. Text to encrypt
2. Encryption certificate (optional)

#### Output(s)
1. Encrypted text
2. Checksum of input


### HpcrJson()
This function generates Base64 of JSON input

```go
import "github.com/Sashwat-K/lib-hpcr/contract"
```

#### Input(s)
1. Text to encode

#### Output(s)
1. Base64 of input
2. Checksum of input


### HpcrJsonEncrypted()
This function generates encrypts JSON and formats text as per `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

```go
import "github.com/Sashwat-K/lib-hpcr/contract"
```

#### Input(s)
1. JSON text to encrypt
2. Encryption certificate (optional)

#### Output(s)
1. Encrypted text
2. Checksum of input


### HpcrTgz()
This function generates base64 of TGZ that contains files under the given folder

```go
import "github.com/Sashwat-K/lib-hpcr/contract"
```

#### Input(s)
1. Path of folder

#### Output(s)
1. Base64 of TGZ where TGZ is contents of given folder


### HpcrTgzEncrypted()
This function first generates base64 of TGZ that contains files under the given folder and then encrypts the data as per `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

#### Input(s)
1. Path of folder

#### Output(s)
1. encrypted base64 of TGZ where TGZ is contents of given folder


### HpcrContractSignedEncrypted()
This function generates a signed and encrypted contract with format `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

```go
import "github.com/Sashwat-K/lib-hpcr/contract"
```

#### Input(s)
1. Contract
2. Encryption certificate (optional)
3. Private Key for signing

#### Output(s)
1. Signed and encrypted contract


### HpcrContractSignedEncryptedContractExpiry()
This function generates a signed and encrypted contract with contract expiry enabled. The output will be of the format `hyper-protect-basic.<encoded-encrypted-password>.<encoded-encrypted-data>`.

```go
import "github.com/Sashwat-K/lib-hpcr/contract"
```

#### Input(s)
1. Contract
2. Encryption certificate (optional)
3. Private Key for signing
4. CA Certificate
5. CA Key
6. CSR Parameter JSON as string
7. CSR PEM file
8. Expiry of contract in number of days

The point 6 and 7 if one of. That is, either CSR parameters or CSR PEM file.

The CSR parameters should be of the format:-

```
"country":  "IN",
"state":    "Karnataka",
"location": "Bangalore",
"org":      "IBM",
"unit":     "ISDL",
"domain":   "HPVS",
"mail":     "sashwat.k@ibm.com"
```

#### Output(s)
1. Signed and encrypted contract


### HpcrSelectImage()
This function selects the latest HPCR image details from image list out from IBM Cloud images API.

```go
import "github.com/Sashwat-K/lib-hpcr/image"
```

#### Input(s)
1. Image JSON from IBM Cloud images API
2. version to select (optional)

#### Output(s)
1. Image ID
2. Image name
3. Image checksum
4. Image version


## Questions
Ping me in slack @Sashwat
