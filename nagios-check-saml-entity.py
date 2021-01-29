#!/usr/bin/env python3
import argparse
import sys

from saml2.config import Config
from saml2.mdstore import MetadataStore
from saml2.mdstore import MetaDataMDX

from urllib.parse import urlparse
import ssl
import socket
from pprint import pprint
from datetime import datetime
from cryptography import x509
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


    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--location',
            help='The location of the metadata file. Can be a path or a URL. ' +
                'Mutually exclusive with the --mdq option',
            )
    # https://github.com/iay/md-query/blob/master/draft-young-md-query.txt#L362
    source.add_argument('--mdq',
            help='The base URL of an MDQ responder. Mutually exclusive with ' +
                'the --location option',
            )

    parser.add_argument('--entity',
            help='the entityID to check',
            required=True
            )

    parser.add_argument('--tls_cert_days',
            help='Minimum number of days the TLS certificate of the SAML ' +
                'Assertion Consumer URL has to be valid',
            type=int,
            )
    parser.add_argument('--saml_cert_days',
            help='Minimum number of days the SAML certificate(s) have to be valid',
            type=int,
            )

    
    
    args = parser.parse_args()
   
    # start with clean slate
    ok_msg = []
    warn_msg = []
    crit_msg = []

    # pprint(args)

    mds = MetadataStore(attrc=None, config=Config())


    if args.mdq is not None:
        url = "{base}/entities/{endpoint}".format(
            base=args.mdq,
            endpoint=MetaDataMDX.sha1_entity_transform(args.entity),
        )
    if urlparse(args.location).scheme in ['http', 'https']:
        url=args.location
        mds.load("remote", url=url)
    else:
        mds.load("local", args.location)


    # Expiration check on the TLS certificate of the SAML ACS URL
    if args.tls_cert_days is not None:
        acs_res = mds.assertion_consumer_service(entity_id=args.entity)
        acs_url = next(iter(acs_res), {}).get("location")
        hostname = urlparse(acs_url).hostname
        if urlparse(acs_url).scheme == 'https':
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname = hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    # pprint(cert)
                    if 'notAfter' in cert:
                        expire_date = datetime.strptime(cert['notAfter'],
                                "%b %d %H:%M:%S %Y %Z")
                        expire_in = expire_date - datetime.now()

                        if expire_in.days < 0:
                            crit_msg.append("TLS certificate for '" + hostname +
                                    "' expired on " + cert['notAfter'] +
                                    " (" + str(abs(expire_in.days)) + " days ago)")
                        elif expire_in.days < args.tls_cert_days:
                            warn_msg.append("TLS certificate for '" + hostname +
                                    "' is valid until " + cert['notAfter'] +
                                    " (expires in " + str(expire_in.days) + " days)")
                        else:
                            ok_msg.append("TLS certificate for '" + hostname +
                                    "' is valid until " + cert['notAfter'] +
                                    " (expires in " + str(expire_in.days) + " days)")
        else:
            warn_msg.append("Non-HTTPS Assertion Consumer Service URL: " + acs_url)

    if args.saml_cert_days is not None:
        certs = list(set(
            mds.certs(entity_id=args.entity, descriptor='any', use='encryption') +
            mds.certs(entity_id=args.entity, descriptor='any', use='signing')))
        if len(certs) > 0:
            for i in certs:
                cert = x509.load_der_x509_certificate(base64.b64decode(i))
                if cert.not_valid_after:
                    expire_in = cert.not_valid_after - datetime.now()

                    if expire_in.days < 0:
                        crit_msg.append("A SAML certificate expired on " +
                                cert.not_valid_after.ctime() +
                                " (" + str(abs(expire_in.days)) + " days ago)")
                    elif expire_in.days < args.saml_cert_days:
                        warn_msg.append("A SAML certificate is valid until " +
                                cert.not_valid_after.ctime() +
                                " (expires in " + str(expire_in.days) + " days)")
                    else:
                        ok_msg.append("A SAML certificate is valid until " +
                                cert.not_valid_after.ctime() +
                                " (expires in " + str(expire_in.days) + " days)")
        else:
            ok_msg.append("No SAML certificates found in metatada for entity " + args.entity)


except Exception as e:
    # pprint(e)
    nagios_exit("UNKNOWN: {0}.".format(e), 3)

# Exit with accumulated message(s)
if crit_msg:
    nagios_exit("CRITICAL: " + ' '.join(crit_msg + warn_msg), 2)
elif warn_msg:
    nagios_exit("WARNING: " + ' '.join(warn_msg), 1)
else:
    nagios_exit("OK: " + '\n'.join(ok_msg), 0)
