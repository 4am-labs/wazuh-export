# wazuh-collect

One script, run as root on each Wazuh manager node, that collects the vulnerability and inventory
evidence 4am Labs needs for a vulnerability assessment, packages it, encrypts it to 4am Labs'
certificate and sends it in one upload.

The full statement of what it reads, writes, sends and leaves behind is the text at the top of
`wazuh-collect.py`. In short:

- It only reads. Every wazuh-db statement and every indexer request is checked against a fixed
  list in the script before it is sent, and anything else stops the run first.
- It needs no account and asks for nothing. Where the Wazuh indexer runs on the same host (an
  all-in-one installation), it signs in with the indexer's own admin certificate, read in place
  by Python's TLS library and never copied, logged or sent. That certificate permits anything on
  the indexer, so what the script does with it is only what its fixed list of requests allows.
- It never reads an agent's key, the cluster key, or the contents of the indexer's private key.
- It sends one file, the package encrypted to 4am Labs' certificate, to
  `https://upload.4amlabs.com/v1/upload`, and only with the upload token 4am Labs gives you.
- Everything it makes is left on the host, readable by root only, so you can see what was sent.
  Its last line gives the command that removes it.

## Running it

4am Labs sends you the commit to fetch, the script's SHA-256 and one upload token per manager
node. On each node, from an administrator's shell, this one command:

```sh
sudo bash -c "curl -fsSLo /root/wazuh-collect.py https://raw.githubusercontent.com/4am-labs/wazuh-export/<commit>/wazuh-collect.py && echo '<sha256>  /root/wazuh-collect.py' | sha256sum -c - && /var/ossec/framework/python/bin/python3 -I /root/wazuh-collect.py --out-dir /root --send '<token>'"
```

The URL names a commit, so its text cannot change, and the command runs nothing unless the file
matches the SHA-256. A worker node sends only its own agents' records.

Without `--send` the package is made and encrypted on the host and nothing is sent; the `.p7m`
file can then be returned to 4am Labs another way.

## What it needs

- A Wazuh manager from 4.8, with the manager's own Python at
  `/var/ossec/framework/python/bin/python3`. On 4.8 and 4.9 it also needs `openssl` on the path,
  to encrypt.
- On the master or a standalone manager, the indexer on the same host, with its admin certificate
  at `/etc/wazuh-indexer/certs/admin.pem` and `admin-key.pem`, as Wazuh's installation assistant
  leaves it. Where the indexer runs on another host, the script stops before reading anything and
  sends nothing; ask 4am Labs.
- Outbound HTTPS (TCP 443) to `upload.4amlabs.com`, and to `raw.githubusercontent.com` to fetch
  the script. The master also connects to its indexer.

On Wazuh before 4.13 the indexer holds no inventory (packages, network, system, hotfixes,
hardware), so the script reads it from the manager's own database, which it does on every
release.

## Encryption

The package is encrypted (CMS) to the certificate in the script, `RECIPIENT_CERTIFICATE`, valid to
2028-10-21, SHA-256 fingerprint
`06:EA:00:D7:4F:15:E6:A2:2A:F1:8B:1A:BE:E8:26:07:86:78:30:33:E0:20:18:1E:03:C5:33:FB:47:4E:77:AB`.
Only 4am Labs holds its private key. How it encrypts depends on the cryptography library the
manager bundles: from Wazuh 4.14, AES-256; on 4.10 to 4.13, whose library offers no choice of
cipher, AES-128; on 4.8 and 4.9, whose library cannot encrypt CMS, the host's
`openssl cms -encrypt -aes256`. Where none of these is available, nothing is sent.

## What it was tested on

This version was run, without sending, on Ubuntu 22.04 managers installed by Wazuh's
installation assistant: 4.14.9 (a cluster master and its worker), 4.10.5 and 4.8.2, each signing in
with the indexer's admin certificate and reading its inventory from the manager's database. The
previous version's whole run, including the upload, was tested on 4.10.5, 4.8.2 and the 4.14.9
worker, and on a Wazuh 4.14.8 cluster. The manager images of 4.8.2, 4.9.2, 4.10.5, 4.11.2, 4.12.0, 4.13.1 and 4.14.9
were checked for the bundled Python and its cryptography library.

## Checking it yourself

The tests use only synthetic data: a fake manager tree, a fake wazuh-db on a Unix socket, a fake
HTTPS indexer serving Wazuh 4.14.8's own index mappings, and a fake upload receiver. They need a
Unix-like system with `openssl` on the path. From this folder:

| Command | What it shows |
| --- | --- |
| `python3 tests/test_wazuh_collect.py` | the test suite |
| `python3 tests/mutate.py` | each safeguard, broken one at a time in a temporary copy, makes the suite fail |
| `python3 tests/run_docker.py` | the suite and the mutants on Python 3.6, and on 3.10 with the cryptography library Wazuh 4.14.8 bundles (needs Docker) |
| `python3 tests/list_fields.py` | each data set's fields, which become the CSV's columns |
| `python3 -I tests/probe_ca.py` (with a manager's Python) | where that Python finds CA certificates to verify the receiver |
| `python3 tests/probe_cms.py` | what an installed cryptography library offers for CMS encryption |
| `python3 -I tests/probe_encrypt.py SCRIPT CERT IN OUT` (with a manager's Python) | which encryption route the script takes on that manager |

Without a cryptography library able to encrypt AES-256 CMS, the encryption tests are skipped and
the runs that send use a stand-in, so the upload path is still tested.

## Questions

Ask 4am Labs through the contact who sent you this.

## Licence

MIT; see `LICENSE`.
