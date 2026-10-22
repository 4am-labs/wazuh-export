#!/usr/bin/env python3
"""Run the suite and the mutants on the oldest supported Python and on the manager's.

    python3 tests/run_docker.py [--keep-images] [3.6] [3.10]

    3.6    python:3.6, no cryptography library: the encryption tests are skipped, and the runs
           that send use the suite's stand-in encryptor
    3.10   python:3.10 with cryptography 48.0.1, as Wazuh 4.14.8's framework pins it
           (framework/requirements.txt line 18): the encryption tests and mutants run

Each run is one container started with --rm, the script's folder mounted read-only. An image this
run had to pull is removed afterwards (unless --keep-images), and its absence is then confirmed
with docker itself; anything left is named with the command that removes it. An image that was
already present is left alone.

Exit 0 when every suite and every mutation run passed.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FOLDER = os.path.dirname(HERE)
RUNS = {
    "3.6": ("python:3.6", ""),
    "3.10": ("python:3.10", "pip install -q --root-user-action=ignore "
                            "--disable-pip-version-check cryptography==48.0.1 && "),
}
INNER = ("{install}python3 tests/test_wazuh_collect.py; s=$?; python3 tests/mutate.py; m=$?; "
         "echo \"suite exit $s, mutants exit $m\"; [ $s -eq 0 ] && [ $m -eq 0 ]")


def image_present(image):
    proc = subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE, universal_newlines=True)
    if proc.returncode == 0:
        return True
    if "No such image" in proc.stderr or "No such object" in proc.stderr:
        return False
    raise RuntimeError("docker image inspect %s failed: %s" % (image, proc.stderr.strip()))


def main(argv):
    keep = "--keep-images" in argv
    versions = [a for a in argv if a != "--keep-images"] or list(RUNS)
    unknown = [v for v in versions if v not in RUNS]
    if unknown:
        print("unknown version(s): %s; choose from %s" % (", ".join(unknown), ", ".join(RUNS)))
        return 2
    failed, pulled = [], []
    for version in versions:
        image, install = RUNS[version]
        if not image_present(image):
            pulled.append(image)
        print("== Python %s (%s) ==" % (version, image), flush=True)
        proc = subprocess.run(["docker", "run", "--rm", "-v", "%s:/src:ro" % FOLDER, "-w", "/src",
                               "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHON_COLORS=0",
                               image, "sh", "-c", INNER.format(install=install)])
        if proc.returncode != 0:
            failed.append(version)
    leftover = []
    for image in pulled:
        if keep:
            print("kept %s, pulled by this run (--keep-images); remove it with: docker image rm %s"
                  % (image, image))
            continue
        proc = subprocess.run(["docker", "image", "rm", image], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, universal_newlines=True)
        if proc.returncode != 0:
            print("could not remove %s: %s" % (image, proc.stdout.strip()))
        try:
            if image_present(image):
                leftover.append(image)
        except RuntimeError as exc:
            print("WARNING: could not confirm %s was removed: %s" % (image, exc))
            leftover.append(image)
    for image in leftover:
        print("WARNING: %s is still present; remove it with: docker image rm %s" % (image, image))
    print("Python %s: %s" % (", ".join(versions),
                             "all passed" if not failed else "FAILED on " + ", ".join(failed)))
    return 1 if failed or leftover else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
