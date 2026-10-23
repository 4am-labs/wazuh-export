#!/usr/bin/env python3
"""Show that the tests fail against deliberately broken copies of the script.

Not a test suite. A passing test means something only once it has been seen to fail. Each
mutant copies wazuh-collect.py into a temporary directory, replaces one exact string (which must
occur exactly once), runs the named tests against the copy through WC_SCRIPT, and requires them
to FAIL. The working tree is never touched.

    python3 tests/mutate.py

Mutants of the encryption need a cryptography library that can encrypt AES-256 CMS, and run only
where it is present (the manager's 3.10 with 48.0.1; tests/run_docker.py). A mutant whose tests
do not finish within MUTANT_TIMEOUT seconds counts as surviving.

Not mutated, on purpose: the guard that stops reading when one row alone exceeds wazuh-db's
answer limit. Removing it makes the read loop forever rather than fail, which no test can catch
in finite time; the test that exercises it is WazuhDb.test_a_row_longer_than_the_limit_stops_
the_run.

Exit 0 when every mutant was caught; 1 otherwise, naming each survivor.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "wazuh-collect.py")
SUITE = os.path.join(HERE, "test_wazuh_collect.py")
MUTANT_TIMEOUT = 600

# (exact text, replacement, tests that must fail, what the mutant breaks)
MUTANTS = [
    # -- the indexer, as the export script checked it --
    ("    if rows != total:", "    if False:",
     ["IndexerReconciliation.test_lost_page_is_incomplete_and_still_sent",
      "IndexerReconciliation.test_page_served_twice",
      "IndexerReconciliation.test_total_disagrees"], "rows must equal the snapshot total"),
    ("    if len(ids) != rows:", "    if False:",
     ["IndexerReconciliation."
      "test_page_replaced_by_a_duplicate_balances_the_count_but_not_the_ids"],
     "document ids must be distinct"),
    ('    if total.get("relation") != "eq":', "    if False:",
     ["IndexerReconciliation.test_total_given_as_a_lower_bound_stops_the_run_unsent"],
     "the total must be exact"),
    ("    context.check_hostname = True", "    context.check_hostname = False",
     ["Refusals.test_certificate_for_another_host"], "host name verification"),
    ("    context.check_hostname = True\n    context.verify_mode = ssl.CERT_REQUIRED",
     "    context.check_hostname = False\n    context.verify_mode = ssl.CERT_NONE",
     ["Refusals.test_wrong_ca", "Proxy.test_intercepting_proxy_fails_verification",
      "Upload.test_receiver_certificate_verified"], "certificate verification"),
    ("def check_allowed(method, path, query):\n",
     "def check_allowed(method, path, query):\n    return\n",
     ["Refusals.test_request_outside_the_allow_list_never_sent"], "the request allow-list"),
    ("set(query) == query_keys", "set(query) <= query_keys",
     ["Refusals.test_request_outside_the_allow_list_never_sent"],
     "a search must carry its scroll parameter"),
    ('    if parts.scheme != "https":\n        raise UsageError',
     '    if parts.scheme not in ("https", "http"):\n        raise UsageError',
     ["Refusals.test_http_url_refused"], "https only"),
    ("    if parts.username or parts.password:", "    if False:",
     ["Refusals.test_credentials_in_url_refused"], "no credentials in the URL"),
    ("                                       urllib.request.HTTPSHandler(context=context),\n"
     "                                       _RefuseRedirect())",
     "                                       urllib.request.HTTPSHandler(context=context),\n"
     "                                       urllib.request.HTTPRedirectHandler())",
     ["Refusals.test_redirect_refused"], "redirects refused by the indexer client"),
    ("    opener = urllib.request.build_opener(urllib.request.ProxyHandler(), handler,\n"
     "                                         _RefuseRedirect())",
     "    opener = urllib.request.build_opener(urllib.request.ProxyHandler(), handler,\n"
     "                                         urllib.request.HTTPRedirectHandler())",
     ["Upload.test_redirect_refused"], "redirects refused by the upload"),
    ("    return urllib.request.build_opener(urllib.request.ProxyHandler(),",
     "    return urllib.request.build_opener(urllib.request.ProxyHandler({}),",
     ["Proxy.test_proxy_honoured_and_logged"], "proxy settings honoured"),
    ("                if unknown:", "                if False:",
     ["IndexerReconciliation.test_unmapped_field_stops_the_run"], "unmapped fields refused"),
    ("            if any(isinstance(item, (dict, list)) for item in value):",
     "            if False:",
     ["IndexerReconciliation.test_list_of_objects_stops_the_run"], "lists of objects refused"),
    ("        if pattern in required:", "        if False:",
     ["IndexerReconciliation.test_required_data_set_with_no_index_is_incomplete",
      "IndexerReconciliation.test_no_packages_index_off_a_manager_is_incomplete"],
     "a required pattern matching no index is incomplete"),
    ("                                MANAGER_REQUIRED_PATTERNS if plan[\"manager\"]",
     "                                REQUIRED_PATTERNS if plan[\"manager\"]",
     ["IndexerReconciliation.test_no_packages_index_on_a_manager_is_noted_not_incomplete"],
     "on a manager only the vulnerabilities are required of the indexer"),
    ("                                        for p in unreconciled]})",
     "                                        for p in ()]})",
     ["IndexerReconciliation.test_lost_page_is_incomplete_and_still_sent"],
     "the CSV's entry names what did not reconcile"),
    ('    if result["count_before"] != total or result["count_after"] != total:',
     "    if False:",
     ["IndexerReconciliation.test_count_moving_during_the_run_is_noted_not_failed"],
     "count drift noted"),
    ("                status, answer = indexer.free(scroll_id)",
     "                status, answer = 200, None",
     ["MasterRun.test_search_contexts_released",
      "IndexerReconciliation.test_unmapped_field_stops_the_run"], "search contexts released"),
    ('            if name.endswith(".csv"):', "            if False:",
     ["IndexerReconciliation.test_lost_page_is_incomplete_and_still_sent"],
     "the CSV in an INCOMPLETE zip ends .incomplete"),
    ('    final_path = stem + (".zip" if complete else "-INCOMPLETE.zip")',
     '    final_path = stem + ".zip"',
     ["IndexerReconciliation.test_lost_page_is_incomplete_and_still_sent"],
     "INCOMPLETE in the zip name"),
    ("    code = EXIT_COMPLETE if complete else EXIT_INCOMPLETE", "    code = EXIT_COMPLETE",
     ["IndexerReconciliation.test_lost_page_is_incomplete_and_still_sent"],
     "exit status 1 when incomplete"),
    ("    fd = os.open(path, flags, 0o600)", "    fd = os.open(path, flags, 0o644)",
     ["MasterRun.test_files_are_owner_only"], "owner-only files"),
    ("tolerate=(401, 403))", "tolerate=())",
     ["IndexerReconciliation.test_version_unreadable_is_recorded_not_failed"],
     "an unreadable version does not stop the run"),
    ('        auth = "user %s" % user\n', '        auth = "user %s" % (user + password)\n',
     ["MasterRun.test_no_secret_anywhere"], "the password never appears in output"),

    # -- one command: the admin certificate, current index names --
    ("        if not self.by_certificate:\n            token = base64",
     "        if True:\n            token = base64",
     ["AdminCertificate.test_the_admin_certificate_signs_in_with_no_account_or_password"],
     "no account credentials are sent with the certificate"),
    ("        context.load_cert_chain(*client_cert)", "        pass",
     ["AdminCertificate.test_the_admin_certificate_signs_in_with_no_account_or_password",
      "AdminCertificate.test_a_key_that_does_not_load_stops_before_anything"],
     "the admin certificate is presented"),
    ("            missing = [p for p in admin_cert if not os.path.isfile(p)]",
     "            missing = []",
     ["AdminCertificate.test_no_certificate_and_no_account_stops_before_anything"],
     "a missing admin certificate is named before anything is read"),
    ('    if plan["auth"] == "account":\n        user = args.user',
     '    if plan["indexer"]:\n        user = args.user',
     ["AdminCertificate.test_the_admin_certificate_signs_in_with_no_account_or_password"],
     "no password prompt with the admin certificate"),
    ('        result["indices"] = [current] if current in mapping else []',
     '        result["indices"] = sorted(mapping)',
     ["IndexNames.test_no_index_of_the_current_name_is_incomplete_whatever_else_is_there"],
     "only the index of the current name is read"),
    ('            name = ((config["cluster"] or {}).get("name") if config["role"] == "master"',
     '            name = (hostname if config["role"] == "master"',
     ["IndexNames.test_only_the_current_names_index_is_read", "MasterRun.test_exit_and_files"],
     "a cluster's indices are named after the cluster"),
    ('                    else hostname)', '                    else "wazuh")',
     ["Roles.test_cluster_disabled_is_standalone_and_reads_everything"],
     "a standalone manager's indices are named after the host"),
    ('_INDEX_ALTERNATIVES = "(?:%s)[A-Za-z0-9._-]{1,128}"', '_INDEX_ALTERNATIVES = "(?:%s).{1,128}"',
     ["Refusals.test_request_outside_the_allow_list_never_sent"],
     "an index name in a request is a plain name"),
    ("            self._fh.flush()", "            pass",
     ["KilledRun.test_killed_run_leaves_the_partial_zip_and_the_log"],
     "the log reaches disk line by line"),
    ('    partial_path = stem + ".zip.partial"', '    partial_path = stem + ".zip"',
     ["KilledRun.test_killed_run_leaves_the_partial_zip_and_the_log"],
     "an unfinished zip is never named as finished"),

    # -- wazuh-db --
    ("def check_sql(command):\n", "def check_sql(command):\n    return\n",
     ["WazuhDb.test_statements_outside_the_list_are_refused",
      "WazuhDb.test_a_refused_statement_never_reaches_the_socket"],
     "the wazuh-db statement allow-list"),
    ("    if size >= WDB_MAX_REPLY:", "    if False:",
     ["WazuhDb.test_answers_over_the_size_limit_are_read_in_smaller_pages",
      "WazuhDb.test_a_row_longer_than_the_limit_stops_the_run"],
     "an answer at wazuh-db's limit is read again in smaller pages"),
    ("    if len(rows) != total:", "    if False:",
     ["WazuhDb.test_rows_missing_from_a_page_do_not_reconcile_but_are_sent",
      "WazuhDb.test_inventory_rows_missing_do_not_reconcile_but_are_sent"],
     "table rows must equal the count"),
    ("        for table in INVENTORY_TABLES:\n            try:",
     "        for table in ():\n            try:",
     ["MasterRun.test_inventory_rows_whole_per_agent"], "every inventory table is read"),
    ('    "inventory": "(?:%s)" % "|".join(INVENTORY_TABLES),', '    "inventory": "[a-z_]+",',
     ["WazuhDb.test_statements_outside_the_list_are_refused"],
     "only the inventory tables are read whole"),
    ('                if not result["reconciled"]:\n                    inventory_failures.append',
     '                if False:\n                    inventory_failures.append',
     ["WazuhDb.test_inventory_rows_missing_do_not_reconcile_but_are_sent"],
     "inventory that does not reconcile marks the package incomplete"),
    ('    if status != "ok":', "    if False:",
     ["WazuhDb.test_an_error_answer_is_recorded_with_its_text"],
     "an error answer is recorded with its text"),
    ('"connection_status", "disconnection_time", "`group`")',
     '"connection_status", "disconnection_time", "`group`", "internal_key")',
     ["MasterRun.test_agent_table_without_keys", "MasterRun.test_no_secret_anywhere"],
     "the agent key is never selected"),
    ('("name", "node_name", "node_type", "disabled")',
     '("name", "node_name", "node_type", "disabled", "key")',
     ["ConfigReading.test_cluster_key_and_indexer_key_never_read",
      "MasterRun.test_node_config_and_scanner_log"], "the cluster key is never read"),
    ('    plan["indexer"] = role != "worker"', '    plan["indexer"] = True',
     ["Roles.test_worker_reads_only_its_agent_databases"],
     "a worker node does not read the indexer"),
    ('    if role in ("master", "standalone"):', "    if True:",
     ["Roles.test_worker_reads_only_its_agent_databases"],
     "a worker node does not read the agent table"),
    ("                        if SCANNER_LOG_TAG in line:", "                        if True:",
     ["MasterRun.test_node_config_and_scanner_log", "MasterRun.test_no_secret_anywhere"],
     "only the scanner's log lines are taken"),
    ("            if ROTATED_LOG.match(name):", "            if True:",
     ["MasterRun.test_node_config_and_scanner_log"], "only rotated ossec logs are read"),
    ("        text = _strip_comments(fh.read())", "        text = fh.read()",
     ["ConfigReading.test_commented_cluster_block_is_ignored"],
     "commented-out configuration is ignored"),

    # -- sending --
    ("    elif recipient:", "    if recipient:",
     ["Refusals.test_wrong_password_stops_unsent_and_keeps_the_token",
      "WazuhDb.test_a_dropped_connection_stops_the_run_unsent"],
     "nothing is sent after a stopping error"),
    ("def check_upload(method, url):\n", "def check_upload(method, url):\n    return\n",
     ["Upload.test_only_the_one_upload_is_allowed"], "the upload allow-list"),
    ('    if not isinstance(receipt, dict) or receipt.get("sha256") != sha256 \\\n'
     '            or receipt.get("size") != len(body):',
     "    if False:",
     ["Upload.test_receipt_that_does_not_match"], "the receipt must match what was sent"),
    ("    if len(blob) > MAX_UPLOAD_BYTES:", "    if False:",
     ["Upload.test_over_the_limit_is_not_sent"], "a package over the limit is not sent"),
    ("        return EXIT_ERROR if args.send is not None else code", "        return code",
     ["Upload.test_no_encryption_means_nothing_sent"],
     "an unencrypted package is a failed send"),
    ("    if token_given and not TOKEN.match(args.send):", "    if False:",
     ["Refusals.test_malformed_token_refused_before_anything"], "the token's form checked"),
    ("        if args.send is not None and not recipient:", "        if False:",
     ["Refusals.test_send_without_a_recipient_certificate_refused_before_anything"],
     "no sending without a recipient certificate"),
    ("            self.body_interrupted = exc\n            return\n",
     "            raise\n",
     ["Upload.test_a_write_error_after_the_head_is_held_back"],
     "a write error on the body is held back"),
    ("def _closed_without_answer(handler, exc, total):\n",
     "def _closed_without_answer(handler, exc, total):\n    return None\n",
     ["Upload.test_receiver_closing_without_an_answer_is_named"],
     "a receiver closing without an answer is named"),
]

# Mutants of the encryption itself, run only where this Python can encrypt AES-256 CMS.
CRYPTO_MUTANTS = [
    ("enveloped.set_content_encryption_algorithm(algorithms.AES256)",
     "enveloped.set_content_encryption_algorithm(algorithms.AES128)",
     ["Encryption.test_structure_names_aes_256"], "AES-256 content encryption"),
    ('    if hasattr(enveloped, "set_content_encryption_algorithm"):', "    if True:",
     ["Encryption.test_a_builder_without_a_cipher_choice_uses_its_default"],
     "a builder without a cipher choice uses its default"),
    ("    if builder is None:\n        return openssl_envelope",
     "    if False:\n        return openssl_envelope",
     ["Encryption.test_no_builder_encrypts_with_openssl"], "no builder falls back to openssl"),
    ('"-encrypt", "-binary", "-aes256"', '"-encrypt", "-binary", "-aes128"',
     ["Encryption.test_no_builder_encrypts_with_openssl"], "openssl asked for AES-256"),
    ("        shutil.rmtree(work, ignore_errors=True)", "        pass",
     ["Encryption.test_no_builder_encrypts_with_openssl"],
     "the certificate's temporary directory is removed"),
    ("    if openssl is None:\n", "    if False:\n",
     ["Encryption.test_no_builder_and_no_openssl_is_not_encrypted"],
     "a missing openssl means not encrypted"),
    ("    if proc.returncode != 0 or not proc.stdout:", "    if not proc.stdout:",
     ["Encryption.test_an_openssl_failure_is_not_encrypted_with_its_text"],
     "an openssl failure means not encrypted"),
    ("    if proc.returncode != 0 or not proc.stdout:", "    if proc.returncode != 0:",
     ["Encryption.test_an_openssl_with_no_output_is_not_encrypted"],
     "an openssl with no output means not encrypted"),
    ("    if not_after <= utc_now():", "    if False:",
     ["Encryption.test_expired_recipient_certificate_refused"],
     "an expired recipient certificate is refused"),
]

# Mutants that only a given interpreter can catch: (mutant, Python versions below which it
# applies). On Python 3.6 a host name mismatch raises ssl.CertificateError, a ValueError; from
# 3.7 it is an OSError, so removing the 3.6 clause changes nothing there.
VERSION_MUTANTS = [
    (("        except (ssl.SSLError, ssl.CertificateError, socket.timeout, OSError) as exc:\n"
      "            # On Python 3.6",
      "        except (ssl.SSLError, socket.timeout, OSError) as exc:\n"
      "            # On Python 3.6",
      ["Refusals.test_certificate_for_another_host"],
      "host name mismatch handled on Python 3.6"), (3, 7)),
    # From 3.10 Python's own default refuses TLS below 1.2, so only older versions show this.
    (("        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1",
      "        pass",
      ["TlsSettings.test_tls_below_1_2_refused"],
      "TLS 1.2 minimum on Python 3.6"), (3, 7)),
]


def can_encrypt():
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
    except ImportError:
        return False
    return hasattr(getattr(pkcs7, "PKCS7EnvelopeBuilder", None),
                   "set_content_encryption_algorithm")


def main():
    with open(SCRIPT, encoding="utf-8") as fh:
        original = fh.read()
    survivors, broken = [], []
    mutants = list(MUTANTS)
    for mutant, below in VERSION_MUTANTS:
        if sys.version_info[:2] < below:
            mutants.append(mutant)
        else:
            print("skipped  %s  [applies to Python below %d.%d]" % ((mutant[3],) + below))
    if can_encrypt():
        mutants.extend(CRYPTO_MUTANTS)
    else:
        for mutant in CRYPTO_MUTANTS:
            print("skipped  %s  [needs a cryptography library that encrypts AES-256 CMS]"
                  % mutant[3])
    for old, new, tests, what in mutants:
        if original.count(old) != 1:
            broken.append("%s: text occurs %d times, expected once" % (what, original.count(old)))
            continue
        work = tempfile.mkdtemp(prefix="wc-mutant-")
        try:
            mutant = os.path.join(work, "wazuh-collect.py")
            with open(mutant, "w", encoding="utf-8") as fh:
                fh.write(original.replace(old, new))
            env = dict(os.environ, WC_SCRIPT=mutant, PYTHON_COLORS="0",
                       PYTHONDONTWRITEBYTECODE="1")
            try:
                proc = subprocess.run([sys.executable, SUITE] + tests, env=env, cwd=work,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      universal_newlines=True, timeout=MUTANT_TIMEOUT)
                last = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
                # Caught only when the tests ran and failed; a mutant that does not even load
                # would also exit non-zero, and proves nothing.
                caught = proc.returncode != 0 and last.startswith("FAILED")
            except subprocess.TimeoutExpired:
                last, caught = "timed out after %ds" % MUTANT_TIMEOUT, False
            print("%-8s %s  [%s]" % ("caught" if caught else "SURVIVED", what, last), flush=True)
            if not caught:
                survivors.append(what)
        finally:
            shutil.rmtree(work, ignore_errors=True)
    for problem in broken:
        print("BROKEN   " + problem)
    print("Python %d.%d: %d mutants, %d caught, %d survived, %d could not be applied"
          % (sys.version_info[0], sys.version_info[1], len(mutants),
             len(mutants) - len(survivors) - len(broken), len(survivors), len(broken)))
    return 0 if not survivors and not broken else 1


if __name__ == "__main__":
    sys.exit(main())
