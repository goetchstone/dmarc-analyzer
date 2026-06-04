#!/usr/bin/env python3
"""
Core tests for dmarc_analyzer: XML/gz parsing and SQLite persistence.

Runs headless: tkinter is stubbed before import, dnspython is optional in the
module, and only the standard library is required. Run from anywhere:

    python3 tests/test_core.py
"""

import gzip
import os
import shutil
import sys
import tempfile
import types

# ── Stub tkinter so the module imports without a display ─────────────────────
for _name in ["tkinter", "tkinter.font", "tkinter.filedialog",
              "tkinter.messagebox", "tkinter.ttk"]:
    sys.modules[_name] = types.ModuleType(_name)
_tk = sys.modules["tkinter"]
_tk.Tk = object
_tk.filedialog = sys.modules["tkinter.filedialog"]
_tk.messagebox = sys.modules["tkinter.messagebox"]
_tk.ttk = sys.modules["tkinter.ttk"]

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
import dmarc_analyzer as da  # noqa: E402

FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "sample_report.xml")

passed = 0


def ok(label):
    global passed
    passed += 1
    print(f"  ok {passed} - {label}")


def main():
    tmp = tempfile.mkdtemp(prefix="dmarc_test_")
    try:
        # ── Parsing: plain XML ────────────────────────────────────────────
        rep = da.parse_report(FIXTURE)
        assert rep["domain"] == "example.com", rep["domain"]
        assert rep["org"] == "example-reporter.net"
        assert rep["policy_p"] == "quarantine"
        assert len(rep["records"]) == 2
        ok("parse .xml: metadata and record count")

        good, bad = rep["records"]
        assert good["overall"] == "pass" and good["count"] == 120
        assert bad["overall"] == "fail" and bad["disposition"] == "quarantine"
        assert bad["header_from"] == "example.com"
        assert bad["envelope_from"] == "spoofer.invalid"
        ok("parse .xml: pass/fail evaluation and identifiers")

        sels = sorted(d["selector"] for d in good["dkim_results"])
        assert sels == ["mail1", "mail2"], sels
        ok("parse .xml: multiple DKIM auth results captured")

        # ── Parsing: gzipped ─────────────────────────────────────────────
        gz_path = os.path.join(tmp, "sample_report.xml.gz")
        with open(FIXTURE, "rb") as fin, gzip.open(gz_path, "wb") as fout:
            fout.write(fin.read())
        rep_gz = da.parse_report(gz_path)
        assert rep_gz["records"][0]["count"] == 120
        ok("parse .xml.gz")

        # ── Parsing: malformed input raises cleanly ──────────────────────
        junk = os.path.join(tmp, "junk.xml")
        with open(junk, "w") as f:
            f.write("this is not xml")
        try:
            da.parse_report(junk)
            raise AssertionError("malformed XML should raise ValueError")
        except ValueError:
            ok("parse: malformed input raises ValueError")

        # ── DB: insert + duplicate rejection ─────────────────────────────
        db = da.ReportDB(os.path.join(tmp, "t.db"))
        rid = db.insert_report(rep)
        assert rid is not None
        assert db.insert_report(da.parse_report(FIXTURE)) is None
        ok("db: insert and duplicate (org, report_id) rejection")

        # ── DB: round trip ───────────────────────────────────────────────
        loaded = db.load_all()
        assert len(loaded) == 1
        lrep = loaded[0]
        assert sum(r["count"] for r in lrep["records"]) == 127
        lbad = next(r for r in lrep["records"] if r["overall"] == "fail")
        assert lbad["dkim_results"][0]["result"] == "fail"
        assert lrep["begin"] == "2026-06-02"
        ok("db: full round trip incl. JSON auth results and dates")

        # ── DB: stats, cascade delete, clear ─────────────────────────────
        assert db.stats() == (1, 2, 127)
        db.delete_report(rid)
        assert db.stats() == (0, 0, 0)
        orphans = db.conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        assert orphans == 0
        ok("db: stats and cascade delete")

        db.insert_report(da.parse_report(FIXTURE))
        db.clear_all()
        assert db.stats() == (0, 0, 0)
        ok("db: clear_all")

        # ── DB: persistence across connections ───────────────────────────
        db.insert_report(da.parse_report(FIXTURE))
        db.conn.close()
        db2 = da.ReportDB(os.path.join(tmp, "t.db"))
        assert len(db2.load_all()) == 1
        db2.conn.close()
        ok("db: survives reconnect (app restart)")

        # ── App class surface used by the build ──────────────────────────
        for meth in ["_load_files", "_setup_mac_open", "_mac_open_documents",
                     "_sync_views", "_update_status"]:
            assert hasattr(da.DMARCApp, meth), meth
        ok("app: expected methods present")

        print(f"\nALL {passed} TESTS PASSED")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
