#!/usr/bin/env python3
"""Encrypt a file with the script's own encryption, as a manager's run would, and say how.

Not a test. Run with a manager's bundled Python, the script and a throwaway certificate mounted:

    /var/ossec/framework/python/bin/python3 -I probe_encrypt.py SCRIPT CERT.pem IN OUT

It loads SCRIPT as a module, calls its encrypt_package on IN's bytes with CERT.pem as the
recipient, writes the CMS file to OUT, and prints what the script reports: the content cipher
(and, where the host's openssl encrypted, which openssl) and the recipient. This shows in the real
image which route the manager's library takes. Decrypt OUT with the throwaway key to check it.
Exit 0 when OUT was written; 1 when the script refused to encrypt, with its reason.
"""

import importlib.util
import json
import sys


def main(argv):
    if len(argv) != 5:
        print("usage: probe_encrypt.py SCRIPT CERT.pem IN OUT")
        return 2
    spec = importlib.util.spec_from_file_location("wazuh_collect", argv[1])
    wc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wc)
    with open(argv[2], encoding="ascii") as fh:
        pem = fh.read()
    with open(argv[3], "rb") as fh:
        data = fh.read()
    try:
        blob, info = wc.encrypt_package(data, pem)
    except wc.NotEncrypted as exc:
        print("not encrypted: %s" % exc)
        return 1
    with open(argv[4], "wb") as fh:
        fh.write(blob)
    print(json.dumps(info, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
