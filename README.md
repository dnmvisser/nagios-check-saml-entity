# nagios-check-saml-entity
Nagios plugin to check various properties of a SAML entity, either from an MDQ,
a regular URL, or a local file path.

Currently implemented checks:

- The validity of the TLS certificate of the Assertion Consumer URL
- The validity of the SAML signing/encryption certificate(s)




# Usage

```
usage: nagios-check-saml-entity.py [-h] (--location LOCATION | --mdq MDQ)
                                   --entity ENTITY
                                   [--acs-url-tls-cert-days ACS_URL_TLS_CERT_DAYS]
                                   [--saml-cert-days SAML_CERT_DAYS]

Check various properties of a SAML entity

optional arguments:
  -h, --help            show this help message and exit
  --location LOCATION   The location of the metadata file. Can be a path or a
                        URL. Mutually exclusive with the --mdq option
  --mdq MDQ             The base URL of an MDQ responder. Mutually exclusive
                        with the --location option
  --entity ENTITY       the entityID to check
  --acs-url-tls-cert-days ACS_URL_TLS_CERT_DAYS
                        Minimum number of days the TLS certificate of the SAML
                        Assertion Consumer URL has to be valid
  --saml-cert-days SAML_CERT_DAYS
                        Minimum number of days the SAML certificate(s) have to
                        be valid
```
