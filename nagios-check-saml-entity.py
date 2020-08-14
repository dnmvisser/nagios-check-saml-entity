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
    parser.add_argument('--entity',
            help='the entityID to check',
            required=True
            )
   
    # https://github.com/iay/md-query/blob/master/draft-young-md-query.txt#L362
    parser.add_argument('--mdq',
            help='The base URL of the MDQ responder',
            required=True
            )
    parser.add_argument('--warning',
            help='Minimum number of days a certificate has to be valid to issue a WARNING',
            type=int,
            default=21
            )

    
    
    args = parser.parse_args()
   
    # start with clean slate
    ok_msg = []
    warn_msg = []
    crit_msg = []


    url = "{base}/entities/{endpoint}".format(
        base=args.mdq,
        endpoint=MetaDataMDX.sha1_entity_transform(args.entity),
    )
    mds = MetadataStore(attrc=None, config=Config())
    mds.load("remote", url=url)
    res = mds.assertion_consumer_service(entity_id=args.entity)
    acs_url = next(iter(res), {}).get("location")

    hostname = urlparse(acs_url).hostname
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname = hostname) as tls_sock:
            cert = tls_sock.getpeercert()
            # pprint(cert)
            if 'notAfter' in cert:
                expire_date = datetime.strptime(cert['notAfter'],
                        "%b %d %H:%M:%S %Y %Z")
                expire_in = expire_date - datetime.now()

                if expire_in.days < 0:
                    crit_msg.append("X.509 certificate '" + hostname +
                            "' expired on " + cert['notAfter'] +
                            " (" + str(abs(expire_in.days)) + " days ago)")
                elif expire_in.days < args.warning:
                    warn_msg.append("X.509 certificate '" + hostname +
                            "' is valid until " + cert['notAfter'] +
                            " (expires in " + str(expire_in.days) + " days)")
                else:
                    ok_msg.append("X.509 certificate '" + hostname +
                            "' is valid until " + cert['notAfter'] +
                            " (expires in " + str(expire_in.days) + " days)")

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
