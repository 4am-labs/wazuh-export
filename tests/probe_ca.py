#!/usr/bin/env python3
"""Show where this Python would find CA certificates to verify the upload receiver with.

Not a test. Run with the manager's own Python, as the script is run:

    /var/ossec/framework/python/bin/python3 -I probe_ca.py

It prints ssl's default verify paths and whether each exists, whether certifi imports and where
its bundle is, and which of the script's SYSTEM_CA_BUNDLES exist: the same order of sources the
script's receiver check tries. Reads only.
"""

import os
import ssl
import sys

SYSTEM_CA_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                     "/etc/ssl/ca-bundle.pem", "/etc/pki/ca-trust/extracted/pem/"
                     "tls-ca-bundle.pem", "/etc/ssl/cert.pem")


def exists(path):
    return "%s (%s)" % (path, "present" if path and os.path.exists(path) else "absent")


def main():
    print("python %s at %s" % (sys.version.split()[0], sys.executable))
    print("openssl %s" % ssl.OPENSSL_VERSION)
    paths = ssl.get_default_verify_paths()
    print("default cafile: %s" % exists(paths.cafile))
    print("default capath: %s" % exists(paths.capath))
    print("openssl cafile: %s" % exists(paths.openssl_cafile))
    print("openssl capath: %s" % exists(paths.openssl_capath))
    try:
        import certifi
        print("certifi %s: %s" % (getattr(certifi, "__version__", "?"), exists(certifi.where())))
    except ImportError:
        print("certifi: not importable")
    for path in SYSTEM_CA_BUNDLES:
        print("system bundle: %s" % exists(path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
