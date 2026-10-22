#!/usr/bin/env python3
"""Show what the installed cryptography library offers for CMS (PKCS#7) enveloping.

Not a test. Run inside the image the manager's bundled Python is modelled on, with the version
the manager's framework pins (4.14.8: framework/requirements.txt line 18):

    docker run --rm -v "$PWD":/src:ro -w /src python:3.10 \\
        sh -c 'pip install -q cryptography==48.0.1 && python3 tests/probe_cms.py'

It prints the library version, whether PKCS7EnvelopeBuilder and pkcs7_decrypt_der exist, which
methods the builder has, then encrypts a sample to a throwaway self-signed certificate and
decrypts it twice: with the library and with `openssl cms -decrypt`, listing the algorithms
openssl reports in the structure. Exit 0 when both decryptions return the sample.
"""

import datetime
import os
import subprocess
import sys
import tempfile

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID


def throwaway_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "probe recipient")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return key, cert


def main():
    print("python %s" % sys.version.split()[0])
    print("cryptography %s" % cryptography.__version__)
    print("PKCS7EnvelopeBuilder: %s" % hasattr(pkcs7, "PKCS7EnvelopeBuilder"))
    print("pkcs7_decrypt_der: %s" % hasattr(pkcs7, "pkcs7_decrypt_der"))
    builder_methods = sorted(m for m in dir(pkcs7.PKCS7EnvelopeBuilder) if not m.startswith("_"))
    print("builder methods: %s" % ", ".join(builder_methods))

    key, cert = throwaway_pair()
    sample = os.urandom(1 << 20)
    blob = (pkcs7.PKCS7EnvelopeBuilder().set_data(sample).add_recipient(cert)
            .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary]))
    print("encrypted %d bytes to %d" % (len(sample), len(blob)))

    ok = True
    if hasattr(pkcs7, "pkcs7_decrypt_der"):
        # Decryption takes only the Text option (48.0.1); binary content needs none.
        back = pkcs7.pkcs7_decrypt_der(blob, cert, key, [])
        print("library decrypt matches: %s" % (back == sample))
        ok = ok and back == sample

    work = tempfile.mkdtemp(prefix="probe-cms-")
    try:
        paths = {n: os.path.join(work, n) for n in ("in.p7m", "key.pem", "cert.pem", "out")}
        with open(paths["in.p7m"], "wb") as fh:
            fh.write(blob)
        with open(paths["key.pem"], "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        with open(paths["cert.pem"], "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        proc = subprocess.run(["openssl", "cms", "-decrypt", "-binary", "-inform", "DER",
                               "-in", paths["in.p7m"], "-recip", paths["cert.pem"],
                               "-inkey", paths["key.pem"], "-out", paths["out"]],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              universal_newlines=True)
        print("openssl cms -decrypt exit %d %s%s" % (proc.returncode, proc.stdout, proc.stderr))
        if proc.returncode == 0:
            with open(paths["out"], "rb") as fh:
                matched = fh.read() == sample
            print("openssl decrypt matches: %s" % matched)
            ok = ok and matched
        else:
            ok = False
        info = subprocess.run(["openssl", "cms", "-cmsout", "-print", "-inform", "DER",
                               "-in", paths["in.p7m"]], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True)
        algorithms = [line.strip() for line in info.stdout.splitlines()
                      if "algorithm:" in line]
        print("algorithms named in the structure: %s" % "; ".join(algorithms))
        if info.returncode != 0:
            print("openssl cms -print failed: %s" % info.stderr)
        version = subprocess.run(["openssl", "version"], stdout=subprocess.PIPE,
                                 universal_newlines=True)
        print("openssl %s" % version.stdout.strip())
    finally:
        for path in os.listdir(work):
            os.remove(os.path.join(work, path))
        os.rmdir(work)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
