#!/usr/bin/env python3
import argparse
import sys

from saml2.config import Config
from saml2.mdstore import MetadataStore
from saml2.mdstore import MetaDataMDX
import saml2

from urllib.parse import urlparse
import ssl
import socket
# from pprint import pprint
from datetime import datetime
from zoneinfo import ZoneInfo
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64

# Debug
# import logging
# logging.basicConfig(level=logging.DEBUG)


def nagios_exit(message, code):
    print(message)
    sys.exit(code)


try:
    parser = argparse.ArgumentParser(
        description='Check various properties of a SAML entity'
    )

    # Where to get the metadata from
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        '--location',
        help='The location of the metadata file. Can be a path or a URL. '
        + 'Mutually exclusive with the --mdq option',
    )
    source.add_argument(
        '--mdq',
        help='The base URL of an MDQ responder. Mutually exclusive with '
        + 'the --location option. Requires --entity',
    )

    parser.add_argument(
        '--entity',
        help='The entityID to check. Required with --mdq, or if '
        + 'the metadata file contains multiple entities',
    )

    parser.add_argument(
        '--acs-url-tls-cert-days',
        help='Minimum number of days the TLS certificate of the SAML '
        + 'Assertion Consumer URL has to be valid',
        type=int,
    )
    parser.add_argument(
        '--saml-cert-days',
        help='Minimum number of days the SAML certificate(s) have to be valid',
        type=int,
    )

    args = parser.parse_args()

    entity = args.entity
    location = args.location
    mdq = args.mdq

    if mdq is not None and entity is None:
        parser.error('When --mdq is used, you also need to supply --entity')

    # start with clean slate
    ok_msg = []
    warn_msg = []
    crit_msg = []

    mds = MetadataStore(attrc=None, config=Config())

    final_url = location if location is not None else mdq
    try:
        if mdq:
            url = '{base}/entities/{endpoint}'.format(
                base=mdq,
                endpoint=MetaDataMDX.sha1_entity_transform(entity),
            )
            mds.load('remote', url=url)
            final_url = url
        elif urlparse(location).scheme in ['http', 'https']:
            mds.load('remote', url=location)
            final_url = location
        else:
            mds.load('local', location)

    except saml2.SAMLError as e:
        # Check if the SAMLError has an underlying cause
        if e.__cause__ is not None:
            # Access and print the cause, which holds the detailed parsing error
            nagios_exit(f'CRITICAL: Failed parsing metadata from {final_url}: {e.__cause__}', 2)
        else:
            # If no specific cause is found, use the generic error
            nagios_exit(f'CRITICAL: Failed parsing from {final_url}: {e}', 2)
    except Exception as e:
        # FIXME in case of HTTP errors, this prints them to stdout?
        # Like "Response status: 404" etc
        nagios_exit(f'CRITICAL: Failed loading metadata: {e}', 2)

    # If no entity argument is given, assume that the document contains only one
    # entity
    if entity is None:
        entity = mds.keys()[0]
    else:
        if entity not in mds.keys():
            nagios_exit(f'CRITICAL: {final_url} did not contain metadata for entity {entity}'
            + f'\nFound entities: {", ".join(mds.keys())}'
            , 2)

    # Expiration check on the TLS certificate of the SAML ACS URL
    if args.acs_url_tls_cert_days:
        # determine if the metadata pertains to an idP or SP
        if 'idpsso_descriptor' in mds[entity]:
            acs_res = mds.single_sign_on_service(entity_id=entity)
        else:
            acs_res = mds.assertion_consumer_service(entity_id=entity)
        acs_url = next(iter(acs_res), {}).get('location')
        hostname = urlparse(acs_url).hostname
        if urlparse(acs_url).scheme == 'https':
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    # pprint(cert)
                    if 'notAfter' in cert:
                        expire_date = datetime.strptime(
                            cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                        )
                        expire_in = expire_date - datetime.now()

                        if expire_in.days < 0:
                            crit_msg.append(
                                'TLS certificate for https://{} expired on {} ({} days ago)'.format(
                                    hostname, cert['notAfter'], abs(expire_in.days)
                                )
                            )
                        elif expire_in.days < args.acs_url_tls_cert_days:
                            warn_msg.append(
                                'TLS certificate for https://{} is valid until {} (expires in {} days)'.format(
                                    hostname, cert['notAfter'], expire_in.days
                                )
                            )
                        else:
                            ok_msg.append(
                                'TLS certificate for https://{} is valid until {} (expires in {} days)'.format(
                                    hostname, cert['notAfter'], expire_in.days
                                )
                            )
        else:
            warn_msg.append('Non-HTTPS Assertion Consumer Service URL: ' + acs_url)

    if args.saml_cert_days:
        _encryption_cert = mds.certs(
            entity_id=entity, descriptor='any', use='encryption'
        )
        _signing_cert = mds.certs(entity_id=entity, descriptor='any', use='signing')
        cert_set = set()
        if len(_encryption_cert) > 0:
            cert_set.add(_encryption_cert[0][1])
        if len(_signing_cert) > 0:
            cert_set.add(_signing_cert[0][1])
        certs = list(cert_set)
        if len(certs) > 0:
            for i in certs:
                cert = x509.load_der_x509_certificate(
                    base64.b64decode(i), default_backend()
                )
                if cert.not_valid_after_utc:
                    expire_in = cert.not_valid_after_utc - datetime.now(ZoneInfo('UTC'))

                    if expire_in.days < 0:
                        crit_msg.append(
                            'A SAML certificate expired on {} ({}) ({} days ago)'.format(
                                cert.not_valid_after_utc.ctime(),
                                cert.not_valid_after_utc.strftime('%Z'),
                                abs(expire_in.days),
                            )
                        )
                    elif expire_in.days < args.saml_cert_days:
                        warn_msg.append(
                            'A SAML certificate is valid until {} ({}) (expires in {} days)'.format(
                                cert.not_valid_after_utc.ctime(),
                                cert.not_valid_after_utc.strftime('%Z'),
                                expire_in.days,
                            )
                        )
                    else:
                        ok_msg.append(
                            'A SAML certificate is valid until {} ({}) (expires in {} days)'.format(
                                cert.not_valid_after_utc.ctime(),
                                cert.not_valid_after_utc.strftime('%Z'),
                                expire_in.days,
                            )
                        )
        else:
            ok_msg.append(f'No SAML certificates found in metadata for entity {entity}')

    else:
        ok_msg.append('Metadata is valid')
        ok_msg.append(f'{final_url} contains valid metadata for entity {entity}')


except Exception as e:
    # pprint(e)
    nagios_exit('UNKNOWN: {0}.'.format(e), 3)

# Exit with accumulated message(s)
if crit_msg:
    nagios_exit('CRITICAL: ' + ' '.join(crit_msg + warn_msg), 2)
elif warn_msg:
    nagios_exit('WARNING: ' + ' '.join(warn_msg), 1)
else:
    nagios_exit('OK: ' + '\n'.join(ok_msg), 0)
