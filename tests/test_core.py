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
import zipfile

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


def expect_rejected(path, fragment):
    """parse_report must raise ValueError mentioning `fragment`."""
    try:
        da.parse_report(path)
    except ValueError as e:
        assert fragment in str(e), f"{fragment!r} not in {e!r}"
        return
    raise AssertionError(f"{os.path.basename(path)} should have been rejected")


def main():
    tmp = tempfile.mkdtemp(prefix="dmarc_test_")

    def write(name, data):
        path = os.path.join(tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    with open(FIXTURE, "rb") as f:
        xml = f.read()
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

        # ── Formats: detected by content, not extension ──────────────────
        for name in ("REPORT.XML.GZ", "report-without-extension"):
            path = os.path.join(tmp, name)
            with gzip.open(path, "wb") as f:
                f.write(xml)
            assert len(da.parse_report(path)["records"]) == 2, name
        ok("parse: gzip detected by content (.GZ, no extension)")

        zpath = os.path.join(tmp, "google.com!example.com!1780358400!1780444799.zip")
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("google.com!example.com!1780358400!1780444799.xml", xml)
        assert da.parse_report(zpath)["records"][0]["count"] == 120
        ok("parse .zip (the format Google sends)")

        two = os.path.join(tmp, "two.zip")
        with zipfile.ZipFile(two, "w") as zf:
            zf.writestr("a.xml", xml)
            zf.writestr("b.xml", xml)
        expect_rejected(two, "one .xml file")
        ok("parse: zip without exactly one .xml is rejected")

        # ── Namespaces and non-DMARC XML ─────────────────────────────────
        ns = xml.replace(b"<feedback>",
                         b'<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">')
        rep_ns = da.parse_report(write("ns.xml", ns))
        assert rep_ns["org"] == "example-reporter.net"
        assert len(rep_ns["records"]) == 2
        ok("parse: report in a default XML namespace (DMARCbis)")

        expect_rejected(write("page.xml", b"<html><body/></html>"),
                        "not a DMARC aggregate report")
        no_id = xml.replace(b"<report_id>fixture-0001-example.com</report_id>", b"")
        expect_rejected(write("no_id.xml", no_id), "no <report_id>")
        ok("parse: non-DMARC XML and reports without report_id are rejected")

        # ── Hostile input ────────────────────────────────────────────────
        laughs = (b'<?xml version="1.0"?><!DOCTYPE feedback ['
                  b'<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>'
                  b'<feedback>&b;</feedback>')
        expect_rejected(write("laughs.xml", laughs), "DTD")
        xxe = (b'<?xml version="1.0"?><!DOCTYPE feedback ['
               b'<!ENTITY x SYSTEM "file:///etc/passwd">]><feedback>&x;</feedback>')
        expect_rejected(write("xxe.xml", xxe), "DTD")
        ok("parse: DTDs refused (entity expansion, external entities)")

        saved = da.MAX_REPORT_BYTES
        da.MAX_REPORT_BYTES = 1000  # fixture is ~2 KB uncompressed
        try:
            expect_rejected(gz_path, "larger than")
            expect_rejected(zpath, "larger than")
            expect_rejected(FIXTURE, "larger than")
        finally:
            da.MAX_REPORT_BYTES = saved
        saved = da.MAX_XML_ELEMENTS
        da.MAX_XML_ELEMENTS = 10
        try:
            expect_rejected(FIXTURE, "XML elements")
        finally:
            da.MAX_XML_ELEMENTS = saved
        ok("parse: size and element caps (decompression bombs)")

        huge = xml.replace(b"<count>7</count>", b"<count>5000000000000000000</count>")
        expect_rejected(write("huge_count.xml", huge), "out of range")
        neg = xml.replace(b"<count>7</count>", b"<count>-150</count>")
        expect_rejected(write("neg_count.xml", neg), "out of range")
        long_org = xml.replace(b"example-reporter.net</org_name>",
                               b"x" * 5000 + b"</org_name>")
        expect_rejected(write("long_org.xml", long_org), "longer than")
        ok("parse: counts range-checked, oversized fields rejected")

        upper = (xml.replace(b"<dkim>pass</dkim>", b"<dkim>Pass</dkim>")
                    .replace(b"<spf>pass</spf>", b"<spf>PASS</spf>"))
        rec0 = da.parse_report(write("upper.xml", upper))["records"][0]
        assert (rec0["dkim_eval"], rec0["spf_eval"], rec0["overall"]) == ("pass", "pass", "pass")
        ok("parse: policy results are case-insensitive")

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

        # ── DB: a failing insert leaves nothing behind ───────────────────
        db3 = da.ReportDB(os.path.join(tmp, "atomic.db"))
        broken = da.parse_report(FIXTURE)
        broken["records"][1]["dkim_results"] = [object()]  # not JSON-serialisable
        try:
            db3.insert_report(broken)
            raise AssertionError("insert of an unserialisable record should fail")
        except TypeError:
            pass
        assert db3.stats() == (0, 0, 0)
        assert db3.insert_report(da.parse_report(FIXTURE)) is not None
        ok("db: insert is atomic")

        # ── DB: stats can't overflow (it runs at every launch) ───────────
        rid3 = db3.load_all()[0]["db_id"]
        db3.conn.executemany("INSERT INTO records (report_fk, count) VALUES (?, ?)",
                             [(rid3, 2**62), (rid3, 2**62)])
        db3.stats()  # SUM() would raise "integer overflow" here
        assert db3.conn.execute("PRAGMA secure_delete").fetchone()[0] == 1
        db3.conn.close()
        ok("db: stats survive huge counts; secure_delete on")

        # ── DNS result colouring ─────────────────────────────────────────
        bg = da.dns_result_bg
        assert bg("DMARC Record",
                  "DNS error: The DNS query name does not exist: _dmarc.passport.com.") == da.FAIL_BG
        assert bg("DMARC Record", "v=DMARC1; p=none; rua=mailto:d@example.com") == da.PASS_BG
        assert bg("SPF Record", "v=spf1 include:_spf.example.com ~all") == da.PASS_BG
        assert bg("DKIM Record", "v=DKIM1; p=") == da.WARN_BG  # revoked key
        assert bg("DKIM Record", "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3") == da.PASS_BG
        assert bg("DKIM Record", "No DKIM record at s1._domainkey.example.com") == da.FAIL_BG
        assert bg("MX Records", "   10  mx.example.com.") == da.SIDEBAR
        if da.DNS_AVAILABLE:  # raised while parsing the name — no network I/O
            assert da.lookup_dmarc("A\\256.example").startswith("DNS error")
        ok("dns: colour from the lookup result, errors never green")

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
