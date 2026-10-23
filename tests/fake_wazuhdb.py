"""A stand-in wazuh-db for tests: its socket framing, its answers, and its silent cut-off.

Synthetic data only. The real wazuh-db (4.14.8, src/wazuh_db/wdb_parser.c) answers "global sql
<statement>" and "agent <id> sql <statement>" by running the statement on SQLite and writing
"ok <JSON array>" into a buffer of OS_MAXSTR (65,536) bytes with snprintf, so a longer answer is
cut short with nothing to say so; a failure is "err <text>". Each row is a JSON object with NULL
columns left out (wdb.c, wdb_exec_row_stmt_multi_column). This fake does the same on SQLite in
memory, with the agent table exactly as schema_global.sql 13 to 43 defines it and sync_info as
schema_agents.sql 456 to 464 defines it; the inventory tables carry a few columns each, since the
script reads them whole whatever their columns.
"""

import json
import os
import socket
import sqlite3
import struct
import threading

OS_MAXSTR = 65536

GLOBAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT,
    register_ip TEXT,
    internal_key TEXT,
    os_name TEXT,
    os_version TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_codename TEXT,
    os_build TEXT,
    os_platform TEXT,
    os_uname TEXT,
    os_arch TEXT,
    version TEXT,
    config_sum TEXT,
    merged_sum TEXT,
    manager_host TEXT,
    node_name TEXT DEFAULT 'unknown',
    date_add INTEGER NOT NULL,
    last_keepalive INTEGER,
    `group` TEXT DEFAULT 'default',
    group_hash TEXT default NULL,
    group_sync_status TEXT NOT NULL CHECK (group_sync_status IN ('synced', 'syncreq')) DEFAULT 'synced',
    sync_status TEXT NOT NULL CHECK (sync_status IN ('synced', 'syncreq', 'syncreq_status', 'syncreq_keepalive')) DEFAULT 'synced',
    connection_status TEXT NOT NULL CHECK (connection_status IN ('pending', 'never_connected', 'active', 'disconnected')) DEFAULT 'never_connected',
    disconnection_time INTEGER DEFAULT 0,
    group_config_status TEXT NOT NULL CHECK (group_config_status IN ('synced', 'not synced')) DEFAULT 'not synced',
    status_code INTEGER DEFAULT 0
);
INSERT INTO agent (id, ip, register_ip, name, date_add, last_keepalive, `group`, connection_status) VALUES (0, '127.0.0.1', '127.0.0.1', 'localhost', strftime('%s','now'), 253402300799, NULL, 'active');
"""

AGENT_SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_info (
    component TEXT PRIMARY KEY,
    last_attempt INTEGER DEFAULT 0,
    last_completion INTEGER DEFAULT 0,
    n_attempts INTEGER DEFAULT 0,
    n_completions INTEGER DEFAULT 0,
    last_manager_checksum TEXT NOT NULL DEFAULT '',
    last_agent_checksum TEXT NOT NULL DEFAULT ''
);
CREATE TABLE sys_osinfo (scan_time TEXT, os_name TEXT);
CREATE TABLE sys_programs (scan_time TEXT, name TEXT);
CREATE TABLE sys_hotfixes (scan_time TEXT, hotfix TEXT);
CREATE TABLE sys_hwinfo (scan_time TEXT, cpu_name TEXT);
CREATE TABLE sys_netiface (scan_time TEXT, name TEXT);
CREATE TABLE sys_netaddr (iface TEXT, address TEXT);
CREATE TABLE sys_netproto (iface TEXT, type TEXT);
"""

COMPONENTS = ("fim", "syscollector-packages", "syscollector-hotfixes", "syscollector-osinfo",
              "syscollector-hwinfo", "syscollector-netinfo", "syscollector-netaddress",
              "syscollector-netproto", "syscollector-ports", "syscollector-processes")

KEY_CANARY = "INTERNAL-KEY-CANARY-"


class FakeWazuhDb:
    """wazuh-db on a Unix socket at <root>/queue/db/wdb, with an agent database file per agent
    so that the script's listing finds them."""

    def __init__(self, root, agents=3, name_length=10, worker_agents=None):
        self.root = root
        self.db_dir = os.path.join(root, "queue", "db")
        os.makedirs(self.db_dir, exist_ok=True)
        self.socket_path = os.path.join(self.db_dir, "wdb")
        self.commands = []
        self.faults = {"err_for": None, "close_for": None, "not_json_for": None,
                       "drop_rows_for": None}
        self._lock = threading.Lock()
        self.global_db = sqlite3.connect(":memory:", check_same_thread=False)
        self.global_db.executescript(GLOBAL_SCHEMA)
        for n in range(1, agents + 1):
            self.global_db.execute(
                "INSERT INTO agent (id, name, ip, register_ip, internal_key, os_name, os_version, "
                "os_platform, version, manager_host, node_name, date_add, last_keepalive, "
                "`group`, connection_status, disconnection_time) VALUES "
                "(?, ?, ?, 'any', ?, 'Ubuntu', '22.04.4 LTS', 'ubuntu', 'Wazuh v4.14.7', "
                "'manager', 'master-node', 1760000000, ?, 'default', ?, ?)",
                (n, ("agent-%03d-" % n) + "x" * name_length, "10.0.%d.%d" % (n // 250, n % 250),
                 KEY_CANARY + "%03d" % n, 1761100000 + n,
                 "active" if n % 4 else "disconnected", 0 if n % 4 else 1761000000))
        self.global_db.commit()
        local = range(1, agents + 1) if worker_agents is None else worker_agents
        self.agent_dbs = {}
        for n in local:
            agent = "%03d" % n
            db = sqlite3.connect(":memory:", check_same_thread=False)
            db.executescript(AGENT_SCHEMA)
            for i, component in enumerate(COMPONENTS):
                db.execute("INSERT INTO sync_info (component, last_attempt, last_completion, "
                           "n_attempts, n_completions) VALUES (?, ?, ?, ?, ?)",
                           (component, 1761000000 + n + i, 1761000000 + n + i, 5, 5))
            db.execute("INSERT INTO sys_osinfo VALUES ('2026/10/20 10:00:00', 'Ubuntu')")
            for p in range(3):
                db.execute("INSERT INTO sys_programs VALUES (?, ?)",
                           ("2026/10/2%d 10:00:00" % p, "pkg-%d" % p))
            db.execute("INSERT INTO sys_hwinfo VALUES ('2026/10/20 10:00:00', 'Synthetic CPU')")
            db.execute("INSERT INTO sys_netiface VALUES ('2026/10/20 10:00:00', 'eth0')")
            db.execute("INSERT INTO sys_netaddr VALUES ('eth0', '10.0.0.%d')" % n)
            db.execute("INSERT INTO sys_netproto VALUES ('eth0', 'ipv4')")
            db.commit()
            self.agent_dbs[agent] = db
            with open(os.path.join(self.db_dir, agent + ".db"), "wb"):
                pass
        with open(os.path.join(self.db_dir, "000.db"), "wb"):
            pass
        with open(os.path.join(self.db_dir, "global.db"), "wb"):
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.socket_path)
        self.sock.listen(16)
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.sock.close()
        try:
            os.remove(self.socket_path)
        except OSError:
            pass
        with self._lock:
            for db in [self.global_db] + list(self.agent_dbs.values()):
                db.close()

    def _accept(self):
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client):
        try:
            size = struct.unpack("<I", self._recv(client, 4))[0]
            command = self._recv(client, size).decode("utf-8")
            with self._lock:
                self.commands.append(command)
            if self.faults["close_for"] and self.faults["close_for"] in command:
                return
            reply = self.answer(command)[:OS_MAXSTR].encode("utf-8")
            client.sendall(struct.pack("<I", len(reply)) + reply)
        except (OSError, struct.error):
            pass
        finally:
            client.close()

    @staticmethod
    def _recv(client, size):
        buf = b""
        while len(buf) < size:
            chunk = client.recv(size - len(buf))
            if not chunk:
                raise OSError("closed")
            buf += chunk
        return buf

    def answer(self, command):
        if self.faults["err_for"] and self.faults["err_for"] in command:
            return "err Cannot execute SQL query"
        if self.faults["not_json_for"] and self.faults["not_json_for"] in command:
            return "ok [{\"n\": "
        actor, _, rest = command.partition(" ")
        if actor == "global":
            db = self.global_db
        elif actor == "agent":
            agent, _, rest = rest.partition(" ")
            db = self.agent_dbs.get(agent)
            if db is None:
                return "err Agent %s database not found" % agent
        else:
            return "err Invalid DB query actor: %s" % actor
        query, _, sql = rest.partition(" ")
        if query != "sql" or not sql:
            return "err Invalid DB query syntax, near '%.32s'" % rest
        try:
            with self._lock:
                cursor = db.execute(sql)
                names = [d[0] for d in cursor.description or ()]
                rows = [{n: v for n, v in zip(names, row) if v is not None}
                        for row in cursor.fetchall()]
        except sqlite3.Error as exc:
            return "err Cannot execute SQL query; %s" % exc
        if self.faults["drop_rows_for"] and self.faults["drop_rows_for"] in command:
            rows = rows[:-1]
        return "ok " + json.dumps(rows, separators=(",", ":"))
