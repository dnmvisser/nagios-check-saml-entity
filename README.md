# nagios-check-saml-entity

Nagios plugin to check various properties of a SAML entity, either from an MDQ,
a regular URL, or a local file path.

Currently implemented checks:

- The validity of the TLS certificate of the Assertion Consumer URL
- The validity of the SAML signing/encryption certificate(s)

## Requirements

- python 3.9 or newer
- [`pysaml2`](https://pypi.org/project/pysaml2/) 7.1 or newer
- [`cryptography`](https://pypi.org/project/cryptography/) v43 or newer
- `xmlsec1`

## Installation

```console
sudo apt-get install python3-minimal xmlsec1
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
usage: nagios-check-saml-entity.py [-h] (--location LOCATION | --mdq MDQ)
                                   [--entity ENTITY]
                                   [--acs-url-tls-cert-days ACS_URL_TLS_CERT_DAYS]
                                   [--saml-cert-days SAML_CERT_DAYS]

Check various properties of a SAML entity

options:
  -h, --help            show this help message and exit
  --location LOCATION   The location of the metadata file. Can be a path or a URL.
                        Mutually exclusive with the --mdq option
  --mdq MDQ             The base URL of an MDQ responder. Mutually exclusive with the
                        --location option. Requires --entity
  --entity ENTITY       The entityID to check. Required with --mdq, or if the metadata
                        file contains multiple entities
  --acs-url-tls-cert-days ACS_URL_TLS_CERT_DAYS
                        Minimum number of days the TLS certificate of the SAML
                        Assertion Consumer URL has to be valid
  --saml-cert-days SAML_CERT_DAYS
                        Minimum number of days the SAML certificate(s) have to be
                        valid
```

## Examples

```console
# Check if the metadata at a URL is valid SAML2 metadata
./nagios-check-saml-entity.py \
  --location https://idp.geant.org/saml2/idp/metadata.php
OK: Metadata is valid
https://idp.geant.org/saml2/idp/metadata.php contains valid metadata for entity https://idp.geant.org
```

```console
# Check the TLS certificate of an entity's Assertion Consumer Service URL, using an MDQ
./nagios-check-saml-entity.py \
  --mdq https://mdx.eduteams.org \
  --entity https://proxy.eduteams.org/metadata/backend.xml \
  --acs-url-tls-cert-days 21
OK: TLS certificate for https://proxy.eduteams.org is valid until Oct 24 14:46:02 2026 GMT (expires in 314 days)
Metadata is valid
https://mdx.eduteams.org/entities/{sha1}e8f62afdeb76720480a6391f69f4d74aeff1c39f contains valid metadata for entity https://proxy.eduteams.org/metadata/backend.xml
```

```console
# Check the expiration of any of the SAML signing/encryption certificates
./nagios-check-saml-entity.py \
  --location https://login.terena.org/wayf/saml2/idp/metadata.php \
  --entity https://login.terena.org/wayf/saml2/idp/metadata.php \
  --saml-cert-days 30
CRITICAL: A SAML certificate expired on Mon Jan 11 15:26:38 2021 (UTC) (1798 days ago)
```
