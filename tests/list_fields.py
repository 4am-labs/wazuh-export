#!/usr/bin/env python3
"""List each data set's fields and types from the mappings fixture: the columns the combined CSV
gets for that data set.

    python3 tests/list_fields.py [tests/fixtures/mappings-4.14.8.json]
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "fixtures", "mappings-4.14.8.json")


def leaves(properties, prefix=""):
    for name, spec in sorted(properties.items()):
        if "properties" in spec:
            for leaf in leaves(spec["properties"], prefix + name + "."):
                yield leaf
        else:
            yield prefix + name, spec.get("type", "(none)")


def main(argv):
    path = argv[0] if argv else DEFAULT
    with open(path, encoding="utf-8") as fh:
        fixture = json.load(fh)
    for pattern, entry in sorted(fixture["patterns"].items()):
        fields = list(leaves(entry["mappings"].get("properties", {})))
        print("%s (%d fields, dynamic=%s)" % (pattern, len(fields),
                                              entry["mappings"].get("dynamic")))
        for name, kind in fields:
            print("  %-45s %s" % (name, kind))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
