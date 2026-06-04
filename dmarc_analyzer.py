#!/usr/bin/env python3
"""
DMARC Report Analyzer
- Parse .xml and .xml.gz DMARC aggregate reports (RFC 7489)
- DNS lookup for DMARC, SPF, DKIM records on any domain
- Drag-and-drop or file picker for reports
- Tabular view with pass/fail highlighting
- Summary stats per report and across reports

Requires: Python 3.9+, dnspython
  pip3 install dnspython
"""

import gzip
import json
import os
import re
import socket
import sqlite3
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ── Colours ──────────────────────────────────────────────────────────────────
# Every widget must set BOTH fg and bg explicitly. macOS Dark Mode flips the
# *default* text color to white; any widget given a hardcoded light bg but a
# default fg becomes white-on-white and unreadable.
TEXT      = "#1a1a1a"
MUTED     = "#6c757d"
PASS_BG   = "#d4edda"
FAIL_BG   = "#f8d7da"
WARN_BG   = "#fff3cd"
NONE_BG   = "#f8f9fa"
HEADER_BG = "#343a40"
HEADER_FG = "#ffffff"
ROW_ALT   = "#f2f2f2"
ACCENT    = "#0d6efd"
APP_BG    = "#ffffff"
SIDEBAR   = "#f8f9fa"
BORDER    = "#dee2e6"


# ── XML Parsing ───────────────────────────────────────────────────────────────

def _txt(el, path, default=""):
    node = el.find(path)
    return node.text.strip() if node is not None and node.text else default


def parse_report(path: str) -> dict:
    """Parse one DMARC XML or XML.gz file into a dict."""
    path = str(path)
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rb") as f:
                raw = f.read()
        else:
            with open(path, "rb") as f:
                raw = f.read()
        root = ET.fromstring(raw)
    except Exception as e:
        raise ValueError(f"Cannot parse {path}: {e}")

    _meta = root.find("report_metadata"); meta = _meta if _meta is not None else ET.Element("x")
    _pol  = root.find("policy_published"); pol  = _pol  if _pol  is not None else ET.Element("x")

    begin_ts = int(_txt(meta, "date_range/begin") or 0)
    end_ts   = int(_txt(meta, "date_range/end")   or 0)

    report = {
        "file":        os.path.basename(path),
        "org":         _txt(meta, "org_name"),
        "report_id":   _txt(meta, "report_id"),
        "begin_ts":    begin_ts,
        "end_ts":      end_ts,
        "begin":       datetime.fromtimestamp(begin_ts, tz=timezone.utc).strftime("%Y-%m-%d") if begin_ts else "",
        "end":         datetime.fromtimestamp(end_ts,   tz=timezone.utc).strftime("%Y-%m-%d") if end_ts   else "",
        "domain":      _txt(pol,  "domain"),
        "policy_p":    _txt(pol,  "p"),
        "policy_sp":   _txt(pol,  "sp"),
        "policy_pct":  _txt(pol,  "pct"),
        "adkim":       _txt(pol,  "adkim"),
        "aspf":        _txt(pol,  "aspf"),
        "records":     [],
    }

    for rec in root.findall("record"):
        _row = rec.find("row")
        row = _row if _row is not None else ET.Element("x")
        _id = rec.find("identifiers")
        ident = _id if _id is not None else ET.Element("x")
        _ar = rec.find("auth_results")
        auth = _ar if _ar is not None else ET.Element("x")

        # Collect all DKIM results
        dkim_results = []
        for d in auth.findall("dkim"):
            dkim_results.append({
                "domain":   _txt(d, "domain"),
                "selector": _txt(d, "selector"),
                "result":   _txt(d, "result"),
            })

        # Collect all SPF results
        spf_results = []
        for s in auth.findall("spf"):
            spf_results.append({
                "domain": _txt(s, "domain"),
                "scope":  _txt(s, "scope"),
                "result": _txt(s, "result"),
            })

        dkim_eval = _txt(row, "policy_evaluated/dkim")
        spf_eval  = _txt(row, "policy_evaluated/spf")
        disp      = _txt(row, "policy_evaluated/disposition")
        count     = int(_txt(row, "count") or 1)

        # Overall result for the record
        if dkim_eval == "pass" or spf_eval == "pass":
            overall = "pass"
        else:
            overall = "fail"

        record = {
            "source_ip":    _txt(row, "source_ip"),
            "count":        count,
            "disposition":  disp,
            "dkim_eval":    dkim_eval,
            "spf_eval":     spf_eval,
            "overall":      overall,
            "header_from":  _txt(ident, "header_from"),
            "envelope_from":_txt(ident, "envelope_from"),
            "dkim_results": dkim_results,
            "spf_results":  spf_results,
        }
        report["records"].append(record)

    return report


# ── SQLite Persistence ────────────────────────────────────────────────────────

class ReportDB:
    """
    Stores parsed reports in SQLite so data survives app restarts.

    Default location (macOS): ~/Library/Application Support/DMARCAnalyzer/dmarc.db
    Duplicate detection: UNIQUE(org, report_id) — re-importing the same file
    is a no-op.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS reports (
        id          INTEGER PRIMARY KEY,
        org         TEXT,
        report_id   TEXT,
        domain      TEXT,
        begin_ts    INTEGER,
        end_ts      INTEGER,
        policy_p    TEXT,
        policy_sp   TEXT,
        policy_pct  TEXT,
        adkim       TEXT,
        aspf        TEXT,
        source_file TEXT,
        imported_at TEXT DEFAULT (datetime('now')),
        UNIQUE(org, report_id)
    );
    CREATE TABLE IF NOT EXISTS records (
        id            INTEGER PRIMARY KEY,
        report_fk     INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
        source_ip     TEXT,
        count         INTEGER,
        disposition   TEXT,
        dkim_eval     TEXT,
        spf_eval      TEXT,
        overall       TEXT,
        header_from   TEXT,
        envelope_from TEXT,
        dkim_results  TEXT,   -- JSON array
        spf_results   TEXT    -- JSON array
    );
    CREATE INDEX IF NOT EXISTS idx_records_report ON records(report_fk);
    CREATE INDEX IF NOT EXISTS idx_records_ip     ON records(source_ip);
    """

    def __init__(self, path: str | None = None):
        if path is None:
            base = Path.home() / "Library" / "Application Support" / "DMARCAnalyzer"
            base.mkdir(parents=True, exist_ok=True)
            path = base / "dmarc.db"
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(self.SCHEMA)
        self.conn.commit()

    def insert_report(self, rep: dict) -> int | None:
        """Insert a parsed report. Returns the new row id, or None if duplicate."""
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO reports
               (org, report_id, domain, begin_ts, end_ts,
                policy_p, policy_sp, policy_pct, adkim, aspf, source_file)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (rep["org"], rep["report_id"], rep["domain"],
             rep["begin_ts"], rep["end_ts"],
             rep["policy_p"], rep["policy_sp"], rep["policy_pct"],
             rep["adkim"], rep["aspf"], rep["file"]))
        if cur.rowcount == 0:
            return None  # duplicate (org, report_id)
        rid = cur.lastrowid
        self.conn.executemany(
            """INSERT INTO records
               (report_fk, source_ip, count, disposition, dkim_eval, spf_eval,
                overall, header_from, envelope_from, dkim_results, spf_results)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            [(rid, r["source_ip"], r["count"], r["disposition"],
              r["dkim_eval"], r["spf_eval"], r["overall"],
              r["header_from"], r["envelope_from"],
              json.dumps(r["dkim_results"]), json.dumps(r["spf_results"]))
             for r in rep["records"]])
        self.conn.commit()
        return rid

    def load_all(self) -> list[dict]:
        """Reconstruct all reports, newest reporting period first."""
        reports = []
        rows = self.conn.execute(
            """SELECT id, org, report_id, domain, begin_ts, end_ts,
                      policy_p, policy_sp, policy_pct, adkim, aspf, source_file
               FROM reports ORDER BY begin_ts DESC, org""").fetchall()
        for (db_id, org, report_id, domain, b, e,
             p, sp, pct, adkim, aspf, src) in rows:
            rep = {
                "db_id": db_id, "org": org, "report_id": report_id,
                "domain": domain, "begin_ts": b, "end_ts": e,
                "begin": datetime.fromtimestamp(b, tz=timezone.utc).strftime("%Y-%m-%d") if b else "",
                "end":   datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%d") if e else "",
                "policy_p": p, "policy_sp": sp, "policy_pct": pct,
                "adkim": adkim, "aspf": aspf, "file": src,
                "records": [],
            }
            recs = self.conn.execute(
                """SELECT source_ip, count, disposition, dkim_eval, spf_eval,
                          overall, header_from, envelope_from,
                          dkim_results, spf_results
                   FROM records WHERE report_fk = ? ORDER BY count DESC""",
                (db_id,)).fetchall()
            for (ip, cnt, disp, dk, sp_, ov, hf, ef, dkj, spj) in recs:
                rep["records"].append({
                    "source_ip": ip, "count": cnt, "disposition": disp,
                    "dkim_eval": dk, "spf_eval": sp_, "overall": ov,
                    "header_from": hf, "envelope_from": ef,
                    "dkim_results": json.loads(dkj or "[]"),
                    "spf_results":  json.loads(spj or "[]"),
                })
            reports.append(rep)
        return reports

    def delete_report(self, db_id: int):
        self.conn.execute("DELETE FROM reports WHERE id = ?", (db_id,))
        self.conn.commit()

    def clear_all(self):
        self.conn.execute("DELETE FROM reports")
        self.conn.commit()

    def stats(self) -> tuple[int, int, int]:
        """(report count, record rows, total message count)"""
        n_rep = self.conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        n_rec, n_msg = self.conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(count), 0) FROM records").fetchone()
        return n_rep, n_rec, n_msg


# ── DNS Lookups ───────────────────────────────────────────────────────────────

def lookup_dmarc(domain: str) -> str:
    if not DNS_AVAILABLE:
        return "dnspython not installed — run: pip3 install dnspython"
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        txts = []
        for rdata in answers:
            s = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if s.startswith("v=DMARC1"):
                txts.append(s)
        return "\n".join(txts) if txts else "No DMARC record found"
    except dns.exception.DNSException as e:
        return f"DNS error: {e}"


def lookup_spf(domain: str) -> str:
    if not DNS_AVAILABLE:
        return "dnspython not installed"
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        txts = []
        for rdata in answers:
            s = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if "v=spf1" in s.lower():
                txts.append(s)
        return "\n".join(txts) if txts else "No SPF record found"
    except dns.exception.DNSException as e:
        return f"DNS error: {e}"


def lookup_mx(domain: str) -> str:
    if not DNS_AVAILABLE:
        return "dnspython not installed"
    try:
        answers = dns.resolver.resolve(domain, "MX")
        lines = sorted(f"{r.preference:5d}  {r.exchange}" for r in answers)
        return "\n".join(lines) if lines else "No MX records found"
    except dns.exception.DNSException as e:
        return f"DNS error: {e}"


def lookup_dkim(domain: str, selector: str) -> str:
    if not DNS_AVAILABLE:
        return "dnspython not installed"
    host = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(host, "TXT")
        txts = []
        for rdata in answers:
            s = b"".join(rdata.strings).decode("utf-8", errors="replace")
            txts.append(s)
        return "\n".join(txts) if txts else f"No DKIM record at {host}"
    except dns.exception.DNSException as e:
        return f"DNS error ({host}): {e}"


def reverse_ip(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── Main Application ──────────────────────────────────────────────────────────

class DMARCApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DMARC Report Analyzer")
        self.geometry("1300x800")
        self.minsize(900, 600)
        self.configure(bg=APP_BG)

        self.reports: list[dict] = []
        self._sort_col = None
        self._sort_rev = False

        self._build_menu()
        self._build_ui()
        self._check_dns()

        # Persistence: load everything previously imported
        self.db = ReportDB()
        self.reports = self.db.load_all()
        self._sync_views()

        # macOS drag-and-drop via tkinterdnd2 if available, else fallback
        self._setup_dnd()
        # Files dropped on the Dock icon / opened via "Open With" (.app builds)
        self._setup_mac_open()

    # ── Menu ─────────────────────────────────────────────────────────────────

    def _build_menu(self):
        menubar = tk.Menu(self)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open Report(s)…", command=self._open_files, accelerator="Cmd+O")
        filemenu.add_command(label="Clear All Reports", command=self._clear_all)
        filemenu.add_separator()
        filemenu.add_command(label="Quit", command=self.quit, accelerator="Cmd+Q")
        menubar.add_cascade(label="File", menu=filemenu)
        self.config(menu=menubar)
        self.bind("<Command-o>", lambda e: self._open_files())
        self.bind("<Command-q>", lambda e: self.quit())

    # ── UI Layout ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Force a deterministic ttk theme. macOS's native 'aqua' theme
        # follows system Dark Mode and ignores most color options (including
        # button faces — the cause of white text on white buttons). 'clam'
        # ships with every Tk 8.6, renders identically in light and dark
        # mode, and honors explicit colors.
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background="white",
                        fieldbackground="white", foreground=TEXT, rowheight=22)
        style.map("Treeview",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", "white")])
        style.configure("Treeview.Heading", background="#e9ecef",
                        foreground=TEXT, relief="flat", padding=(4, 4))
        style.map("Treeview.Heading", background=[("active", "#dde1e5")])
        style.configure("TButton", foreground=TEXT, padding=(10, 5))
        style.configure("Accent.TButton", background=ACCENT, foreground="white")
        style.map("Accent.TButton",
                  background=[("active", "#0b5ed7"), ("pressed", "#0a58ca")])
        style.configure("Danger.TButton", background="#dc3545", foreground="white")
        style.map("Danger.TButton",
                  background=[("active", "#bb2d3b"), ("pressed", "#a52834")])
        style.configure("TCheckbutton", background=SIDEBAR, foreground=TEXT)
        style.configure("TNotebook.Tab", padding=(14, 6))

        # Top toolbar
        toolbar = tk.Frame(self, bg=HEADER_BG, height=44)
        toolbar.pack(fill=tk.X)
        toolbar.pack_propagate(False)

        title_lbl = tk.Label(toolbar, text="DMARC Report Analyzer",
                             bg=HEADER_BG, fg=HEADER_FG,
                             font=("Helvetica", 14, "bold"))
        title_lbl.pack(side=tk.LEFT, padx=14, pady=8)

        self.dns_badge = tk.Label(toolbar, text="", bg=HEADER_BG, fg="#adb5bd",
                                  font=("Helvetica", 10))
        self.dns_badge.pack(side=tk.RIGHT, padx=12)

        btn_open = ttk.Button(toolbar, text="Open Files…", style="Accent.TButton",
                              command=self._open_files, cursor="hand2")
        btn_open.pack(side=tk.RIGHT, padx=8, pady=6)

        # Status bar — packed before the notebook so it keeps its space
        statusbar = tk.Frame(self, bg=SIDEBAR, height=24)
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        statusbar.pack_propagate(False)
        self.status_lbl = tk.Label(statusbar, text="", bg=SIDEBAR, fg="#6c757d",
                                   anchor=tk.W, font=("Helvetica", 10))
        self.status_lbl.pack(fill=tk.X, padx=10)

        # Notebook: Reports | DNS Lookup
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill=tk.BOTH, expand=True)

        self._build_reports_tab()
        self._build_dns_tab()

    # ── Reports Tab ───────────────────────────────────────────────────────────

    def _build_reports_tab(self):
        frame = tk.Frame(self.nb, bg=APP_BG)
        self.nb.add(frame, text="  Reports  ")

        # Drop zone (shown when no reports loaded)
        self.drop_frame = tk.Frame(frame, bg=SIDEBAR, relief=tk.FLAT,
                                   highlightbackground=BORDER,
                                   highlightthickness=2)
        self.drop_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER,
                              width=420, height=200)

        tk.Label(self.drop_frame, text="⬇", font=("Helvetica", 48),
                 bg=SIDEBAR, fg="#adb5bd").pack(pady=(28, 4))
        tk.Label(self.drop_frame,
                 text="Drop DMARC XML or .xml.gz files here\nor click  Open Files…  above",
                 bg=SIDEBAR, fg="#6c757d", font=("Helvetica", 12),
                 justify=tk.CENTER).pack()

        # Paned: left = report list, right = record detail
        pane = tk.PanedWindow(frame, orient=tk.HORIZONTAL,
                               sashwidth=5, bg=BORDER)
        pane.pack(fill=tk.BOTH, expand=True)

        # Left panel: loaded report list
        left = tk.Frame(pane, bg=SIDEBAR, width=260)
        pane.add(left, minsize=200)

        lbl = tk.Label(left, text="Loaded Reports", bg=SIDEBAR, fg=TEXT,
                       font=("Helvetica", 11, "bold"), anchor=tk.W)
        lbl.pack(fill=tk.X, padx=10, pady=(8, 4))

        listframe = tk.Frame(left, bg=SIDEBAR)
        listframe.pack(fill=tk.BOTH, expand=True, padx=4)

        sb = tk.Scrollbar(listframe)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.report_list = tk.Listbox(listframe, yscrollcommand=sb.set,
                                       bg=SIDEBAR, fg=TEXT, relief=tk.FLAT,
                                       selectbackground=ACCENT,
                                       selectforeground="white",
                                       font=("Helvetica", 10),
                                       activestyle="none",
                                       borderwidth=0)
        self.report_list.pack(fill=tk.BOTH, expand=True)
        sb.config(command=self.report_list.yview)
        self.report_list.bind("<<ListboxSelect>>", self._on_report_select)

        # Summary label under list
        self.summary_lbl = tk.Label(left, text="", bg=SIDEBAR,
                                     fg="#6c757d", font=("Helvetica", 9),
                                     justify=tk.LEFT, anchor=tk.W,
                                     wraplength=240)
        self.summary_lbl.pack(fill=tk.X, padx=10, pady=6)

        btn_frame = tk.Frame(left, bg=SIDEBAR)
        btn_frame.pack(fill=tk.X, padx=6, pady=(0, 8))
        ttk.Button(btn_frame, text="Remove", style="Danger.TButton",
                   command=self._remove_selected,
                   cursor="hand2").pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="Clear All",
                   command=self._clear_all,
                   cursor="hand2").pack(side=tk.LEFT, padx=4)

        # Right panel: records table
        right = tk.Frame(pane, bg=APP_BG)
        pane.add(right, minsize=600)

        # Filter bar
        fbar = tk.Frame(right, bg=SIDEBAR, pady=4)
        fbar.pack(fill=tk.X)
        tk.Label(fbar, text="Filter:", bg=SIDEBAR, fg=TEXT,
                 font=("Helvetica", 10)).pack(side=tk.LEFT, padx=(8, 4))
        self.filter_var = tk.StringVar(master=self)
        self.filter_var.trace_add("write", lambda *_: self._refresh_table())
        filter_entry = tk.Entry(fbar, textvariable=self.filter_var, width=30,
                                bg="white", fg=TEXT, insertbackground=TEXT, relief=tk.FLAT,
                                highlightthickness=1, highlightbackground=BORDER,
                                highlightcolor=ACCENT)
        filter_entry.pack(side=tk.LEFT, padx=4)

        self.show_fails_var = tk.BooleanVar(master=self, value=False)
        ttk.Checkbutton(fbar, text="Failures only", variable=self.show_fails_var,
                        command=self._refresh_table).pack(side=tk.LEFT, padx=8)

        self.stat_lbl = tk.Label(fbar, text="", bg=SIDEBAR, fg="#6c757d",
                                  font=("Helvetica", 9))
        self.stat_lbl.pack(side=tk.RIGHT, padx=12)

        # Table
        cols = ("Source IP", "Count", "Disposition", "DKIM", "SPF",
                "Overall", "Header From", "Envelope From", "Org", "Report Date")
        tbl_frame = tk.Frame(right, bg=APP_BG)
        tbl_frame.pack(fill=tk.BOTH, expand=True)

        xsb = ttk.Scrollbar(tbl_frame, orient=tk.HORIZONTAL)
        xsb.pack(side=tk.BOTTOM, fill=tk.X)
        ysb = ttk.Scrollbar(tbl_frame)
        ysb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(tbl_frame, columns=cols, show="headings",
                                  yscrollcommand=ysb.set,
                                  xscrollcommand=xsb.set,
                                  selectmode="browse")
        self.tree.pack(fill=tk.BOTH, expand=True)
        ysb.config(command=self.tree.yview)
        xsb.config(command=self.tree.xview)

        col_widths = {
            "Source IP": 130, "Count": 60, "Disposition": 90,
            "DKIM": 65, "SPF": 65, "Overall": 70,
            "Header From": 160, "Envelope From": 190,
            "Org": 150, "Report Date": 110,
        }
        for col in cols:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=col_widths.get(col, 100),
                             minwidth=50, anchor=tk.W)

        # Tag colours
        self.tree.tag_configure("pass",    background=PASS_BG, foreground=TEXT)
        self.tree.tag_configure("fail",    background=FAIL_BG, foreground=TEXT)
        self.tree.tag_configure("warn",    background=WARN_BG, foreground=TEXT)
        self.tree.tag_configure("neutral", background=NONE_BG, foreground=TEXT)
        self.tree.tag_configure("alt",     background=ROW_ALT, foreground=TEXT)

        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

        # Detail pane below table
        detail_outer = tk.Frame(right, bg=SIDEBAR, height=130)
        detail_outer.pack(fill=tk.X)
        detail_outer.pack_propagate(False)

        tk.Label(detail_outer, text="Record Detail",
                 bg=SIDEBAR, fg=TEXT, font=("Helvetica", 9, "bold"),
                 anchor=tk.W).pack(fill=tk.X, padx=8, pady=(6, 0))
        self.detail_text = tk.Text(detail_outer, height=6, bg=SIDEBAR, fg=TEXT,
                                    relief=tk.FLAT, font=("Courier", 10),
                                    state=tk.DISABLED, wrap=tk.WORD)
        self.detail_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 6))

        self._report_frame = right
        self._all_rows: list[tuple] = []  # raw rows for filtering

    # ── DNS Tab ───────────────────────────────────────────────────────────────

    def _build_dns_tab(self):
        frame = tk.Frame(self.nb, bg=APP_BG)
        self.nb.add(frame, text="  DNS Lookup  ")

        top = tk.Frame(frame, bg=SIDEBAR, pady=8)
        top.pack(fill=tk.X)

        tk.Label(top, text="Domain:", bg=SIDEBAR, fg=TEXT,
                 font=("Helvetica", 11)).pack(side=tk.LEFT, padx=(12, 4))
        self.dns_domain_var = tk.StringVar(master=self, value="")
        domain_entry = tk.Entry(top, textvariable=self.dns_domain_var,
                                width=28, font=("Helvetica", 11),
                                bg="white", fg=TEXT, insertbackground=TEXT, relief=tk.FLAT,
                                highlightthickness=1, highlightbackground=BORDER,
                                highlightcolor=ACCENT)
        self.domain_entry = domain_entry
        domain_entry.pack(side=tk.LEFT, padx=4)
        domain_entry.bind("<Return>", lambda e: self._run_dns_lookup())

        tk.Label(top, text="DKIM selector:", bg=SIDEBAR, fg=TEXT,
                 font=("Helvetica", 11)).pack(side=tk.LEFT, padx=(12, 4))
        self.dkim_sel_var = tk.StringVar(master=self, value="google")
        sel_entry = tk.Entry(top, textvariable=self.dkim_sel_var,
                             width=12, font=("Helvetica", 11),
                             bg="white", fg=TEXT, insertbackground=TEXT, relief=tk.FLAT,
                                highlightthickness=1, highlightbackground=BORDER,
                                highlightcolor=ACCENT)
        sel_entry.pack(side=tk.LEFT, padx=4)

        ttk.Button(top, text="Look Up", style="Accent.TButton",
                   command=self._run_dns_lookup,
                   cursor="hand2").pack(side=tk.LEFT, padx=10)

        self.dns_spin_lbl = tk.Label(top, text="", bg=SIDEBAR, fg="#6c757d")
        self.dns_spin_lbl.pack(side=tk.LEFT)

        # Results grid: four labelled sections
        results_frame = tk.Frame(frame, bg=APP_BG)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)
        results_frame.columnconfigure(0, weight=1)
        results_frame.columnconfigure(1, weight=1)

        self._dns_widgets = {}
        sections = [
            ("DMARC Record", "_dmarc.{domain}", 0, 0),
            ("SPF Record",   "{domain} TXT",     0, 1),
            ("DKIM Record",  "{selector}._domainkey.{domain}", 1, 0),
            ("MX Records",   "{domain} MX",      1, 1),
        ]
        for title, subtitle, row, col in sections:
            sec = tk.LabelFrame(results_frame, text=f" {title} ",
                                bg=APP_BG, font=("Helvetica", 10, "bold"),
                                fg="#495057", relief=tk.GROOVE)
            sec.grid(row=row, column=col, sticky="nsew",
                     padx=6, pady=6, ipady=4)
            results_frame.rowconfigure(row, weight=1)

            sub = tk.Label(sec, text=subtitle, bg=APP_BG, fg="#adb5bd",
                           font=("Helvetica", 9, "italic"))
            sub.pack(anchor=tk.W, padx=8)

            txt = tk.Text(sec, height=6, bg=SIDEBAR, fg=TEXT, relief=tk.FLAT,
                          font=("Courier", 10), wrap=tk.WORD,
                          state=tk.DISABLED)
            txt.pack(fill=tk.BOTH, expand=True, padx=6, pady=(2, 6))
            self._dns_widgets[title] = (txt, sub)

    # ── DNS Logic ─────────────────────────────────────────────────────────────

    def _check_dns(self):
        if DNS_AVAILABLE:
            self.dns_badge.config(text="DNS ✓", fg="#28a745")
        else:
            self.dns_badge.config(text="DNS unavailable — pip3 install dnspython", fg="#dc3545")

    def _run_dns_lookup(self):
        domain   = self.dns_domain_var.get().strip().lower()
        selector = self.dkim_sel_var.get().strip()
        if not domain:
            messagebox.showwarning("No domain", "Enter a domain name first.",
                                   parent=self)
            self.domain_entry.focus_set()
            return
        self.dns_spin_lbl.config(text="Looking up…")
        self.update_idletasks()

        def _do():
            results = {
                "DMARC Record": lookup_dmarc(domain),
                "SPF Record":   lookup_spf(domain),
                "DKIM Record":  lookup_dkim(domain, selector) if selector else "(no selector entered)",
                "MX Records":   lookup_mx(domain),
            }
            subtitles = {
                "DMARC Record": f"_dmarc.{domain}",
                "SPF Record":   f"{domain} TXT",
                "DKIM Record":  f"{selector}._domainkey.{domain}" if selector else "",
                "MX Records":   f"{domain} MX",
            }
            self.after(0, lambda: self._show_dns_results(results, subtitles))

        threading.Thread(target=_do, daemon=True).start()

    def _show_dns_results(self, results, subtitles):
        self.dns_spin_lbl.config(text="")
        for title, (txt_widget, sub_lbl) in self._dns_widgets.items():
            sub_lbl.config(text=subtitles.get(title, ""))
            txt_widget.config(state=tk.NORMAL)
            txt_widget.delete("1.0", tk.END)
            val = results.get(title, "")
            txt_widget.insert(tk.END, val)
            # Colour background based on content
            if "pass" in val.lower() or val.startswith("v="):
                txt_widget.config(bg=PASS_BG)
            elif "not found" in val.lower() or "no " in val.lower() or "error" in val.lower():
                txt_widget.config(bg=FAIL_BG)
            else:
                txt_widget.config(bg=SIDEBAR)
            txt_widget.config(state=tk.DISABLED)

    # ── File Loading ──────────────────────────────────────────────────────────

    def _open_files(self):
        # filetypes must stay single-dot patterns: a compound extension like
        # "*.xml.gz" raises an NSException inside macOS's native open dialog
        # and kills the whole process. "*.*" is also invalid on macOS; the
        # any-file pattern is "*".
        paths = filedialog.askopenfilenames(
            parent=self,
            title="Select DMARC Report Files",
            filetypes=[
                ("DMARC reports", "*.xml"),
                ("Compressed reports", "*.gz"),
                ("All files", "*"),
            ],
        )
        self._load_files(paths)

    def _load_files(self, paths):
        if not paths:
            return
        imported, skipped, errors = 0, 0, []
        first_new_id = None

        for path in paths:
            try:
                rep = parse_report(path)
                rid = self.db.insert_report(rep)
                if rid is None:
                    skipped += 1
                else:
                    imported += 1
                    if first_new_id is None:
                        first_new_id = rid
            except Exception as e:
                errors.append(f"{os.path.basename(str(path))}: {e}")

        if errors:
            messagebox.showerror("Parse errors", "\n".join(errors))

        self.reports = self.db.load_all()
        self._sync_views(select_db_id=first_new_id)

        msg = f"Imported {imported}"
        if skipped:
            msg += f", skipped {skipped} duplicate(s)"
        self._update_status(msg)

    def _sync_views(self, select_db_id=None):
        """Refresh report list / drop zone / table after any DB change."""
        self._refresh_report_list()
        if self.reports:
            self.drop_frame.place_forget()
            idx = 0
            if select_db_id is not None:
                for i, r in enumerate(self.reports):
                    if r.get("db_id") == select_db_id:
                        idx = i
                        break
            self.report_list.selection_clear(0, tk.END)
            self.report_list.selection_set(idx)
            self.report_list.see(idx)
            self._on_report_select(None)
        else:
            self.drop_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER,
                                  width=420, height=200)
            self.drop_frame.lift()  # created before the pane; raise above it
            self._clear_table()
            self._all_rows = []
            self.summary_lbl.config(text="")
            self.stat_lbl.config(text="")
        self._update_status()

    def _update_status(self, extra=""):
        n_rep, n_rec, n_msg = self.db.stats()
        short_path = self.db.path.replace(str(Path.home()), "~")
        base = f"DB: {short_path}  ·  {n_rep} reports · {n_rec} rows · {n_msg:,} messages"
        self.status_lbl.config(text=(extra + "   |   " if extra else "") + base)

    def _refresh_report_list(self):
        self.report_list.delete(0, tk.END)
        for r in self.reports:
            n_fail = sum(1 for rec in r["records"] if rec["overall"] == "fail")
            label = f"{r['org']}  ({r['begin']})"
            if n_fail:
                label += f"  ⚠ {n_fail}"
            self.report_list.insert(tk.END, label)

    def _remove_selected(self):
        sel = self.report_list.curselection()
        if not sel:
            return
        rep = self.reports[sel[0]]
        if not messagebox.askyesno(
                "Remove report",
                f"Permanently delete this report from the database?\n\n"
                f"{rep['org']} — {rep['begin']}\n"
                f"{len(rep['records'])} record rows"):
            return
        self.db.delete_report(rep["db_id"])
        self.reports = self.db.load_all()
        self._sync_views()

    def _clear_all(self):
        if not self.reports:
            return
        n_rep, n_rec, _ = self.db.stats()
        if not messagebox.askyesno(
                "Clear all",
                f"Permanently delete ALL {n_rep} reports "
                f"({n_rec} rows) from the database?\n\nThis cannot be undone."):
            return
        self.db.clear_all()
        self.reports = []
        self._sync_views()

    # ── Table Population ──────────────────────────────────────────────────────

    def _on_report_select(self, event):
        sel = self.report_list.curselection()
        if not sel:
            return
        idx = sel[0]
        rep = self.reports[idx]
        self._populate_table(rep)

        # Summary
        total   = sum(rec["count"] for rec in rep["records"])
        n_pass  = sum(rec["count"] for rec in rep["records"] if rec["overall"] == "pass")
        n_fail  = sum(rec["count"] for rec in rep["records"] if rec["overall"] == "fail")
        pct     = f"{100*n_pass//total}%" if total else "—"
        summary = (
            f"Domain: {rep['domain']}\n"
            f"Policy: p={rep['policy_p']} sp={rep['policy_sp']} pct={rep['policy_pct']}%\n"
            f"adkim={rep['adkim']}  aspf={rep['aspf']}\n"
            f"Messages: {total:,}  Pass: {n_pass:,}  Fail: {n_fail:,}  ({pct} pass rate)\n"
            f"Period: {rep['begin']} → {rep['end']}"
        )
        self.summary_lbl.config(text=summary)

        # Prefill DNS domain from report
        self.dns_domain_var.set(rep["domain"])

    def _populate_table(self, rep: dict):
        self._all_rows = []
        for rec in rep["records"]:
            dkim_auth = ", ".join(
                f"{d['selector']}:{d['result']}" if d['selector'] else d['result']
                for d in rec["dkim_results"]
            ) or rec["dkim_eval"]
            spf_auth = ", ".join(
                f"{s['domain']}:{s['result']}" for s in rec["spf_results"]
            ) or rec["spf_eval"]

            row = (
                rec["source_ip"],
                str(rec["count"]),
                rec["disposition"],
                rec["dkim_eval"],
                rec["spf_eval"],
                rec["overall"],
                rec["header_from"],
                rec["envelope_from"],
                rep["org"],
                rep["begin"],
            )
            self._all_rows.append((row, rec, rep))
        self._refresh_table()

    def _refresh_table(self):
        ftext = self.filter_var.get().lower()
        fails_only = self.show_fails_var.get()

        self._clear_table()
        shown = 0
        for i, (row, rec, rep) in enumerate(self._all_rows):
            if fails_only and rec["overall"] != "fail":
                continue
            if ftext and not any(ftext in str(v).lower() for v in row):
                continue

            tag = rec["overall"]  # "pass" or "fail"
            if tag == "pass" and i % 2 == 0:
                tag = "neutral"  # alternate row
            self.tree.insert("", tk.END, values=row, tags=(tag,))
            shown += 1

        total = sum(rec["count"] for _, rec, _ in self._all_rows)
        self.stat_lbl.config(text=f"{shown} rows shown  |  {total:,} total messages")

    def _clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _on_row_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        values = self.tree.item(sel[0], "values")
        if not values:
            return

        # Find matching record for detail
        src_ip = values[0]
        count  = values[1]
        matched_rec = matched_rep = None
        for row, rec, rep in self._all_rows:
            if row[0] == src_ip and row[1] == count:
                matched_rec = rec
                matched_rep = rep
                break

        if not matched_rec:
            return

        lines = [
            f"Source IP:     {matched_rec['source_ip']}",
            f"Count:         {matched_rec['count']}",
            f"Disposition:   {matched_rec['disposition']}",
            f"DKIM (eval):   {matched_rec['dkim_eval']}",
            f"SPF  (eval):   {matched_rec['spf_eval']}",
            f"Header From:   {matched_rec['header_from']}",
            f"Envelope From: {matched_rec['envelope_from']}",
            "",
        ]
        for d in matched_rec["dkim_results"]:
            lines.append(f"DKIM auth:  domain={d['domain']}  selector={d['selector']}  result={d['result']}")
        for s in matched_rec["spf_results"]:
            lines.append(f"SPF  auth:  domain={s['domain']}  scope={s['scope']}  result={s['result']}")

        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "\n".join(lines))
        self.detail_text.config(state=tk.DISABLED)

        # Also jump to DNS tab and populate domain
        if matched_rep:
            self.dns_domain_var.set(matched_rep["domain"])

    # ── Sorting ───────────────────────────────────────────────────────────────

    def _sort_by(self, col):
        cols = ("Source IP", "Count", "Disposition", "DKIM", "SPF",
                "Overall", "Header From", "Envelope From", "Org", "Report Date")
        if col not in cols:
            return
        idx = cols.index(col)

        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = False

        def key(item):
            v = self.tree.item(item, "values")[idx]
            try:
                return int(v)
            except ValueError:
                return v.lower()

        items = list(self.tree.get_children(""))
        items.sort(key=key, reverse=self._sort_rev)
        for i, item in enumerate(items):
            self.tree.move(item, "", i)

        # Update heading to show sort direction
        for c in cols:
            arrow = ""
            if c == col:
                arrow = " ▲" if not self._sort_rev else " ▼"
            self.tree.heading(c, text=c + arrow)

    # ── Drag and Drop ─────────────────────────────────────────────────────────

    def _setup_dnd(self):
        """
        Native drag-and-drop requires tkinterdnd2 (pip3 install tkinterdnd2).
        When it's installed, main() builds the app on a TkinterDnD root, so
        drop_target_register exists. Without it, this raises AttributeError
        and we silently fall back to the file picker.
        """
        try:
            from tkinterdnd2 import DND_FILES
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_dnd_drop)
        except Exception:
            pass  # Fallback: use file picker only

    def _on_dnd_drop(self, event):
        # tkinterdnd2 returns a brace-wrapped string on macOS
        raw = event.data
        paths = []
        if raw.startswith("{"):
            import re
            paths = re.findall(r'\{([^}]+)\}', raw)
            remainder = re.sub(r'\{[^}]+\}', '', raw).split()
            paths.extend(remainder)
        else:
            paths = raw.split()
        self._load_files([p.strip() for p in paths if p.strip()])

    def _setup_mac_open(self):
        """
        When running as a macOS .app bundle, Finder delivers files dropped on
        the Dock icon (or opened via "Open With") through the Tk command
        ::tk::mac::OpenDocument. Registering it costs nothing on other
        platforms or when running as a plain script.
        """
        try:
            self.createcommand("::tk::mac::OpenDocument", self._mac_open_documents)
        except Exception:
            pass

    def _mac_open_documents(self, *paths):
        if paths:
            self._load_files(paths)


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    try:
        from tkinterdnd2 import TkinterDnD

        # MRO: _App → DMARCApp → TkinterDnD.Tk → tk.Tk
        # DMARCApp.__init__'s super().__init__() lands on TkinterDnD.Tk,
        # which initializes Tk once and loads the tkdnd extension.
        class _App(DMARCApp, TkinterDnD.Tk):
            pass

        app = _App()
    except Exception:
        # tkinterdnd2 absent (ImportError) OR present but its compiled tkdnd
        # library failed to load (RuntimeError — seen in frozen/PyInstaller
        # builds). A windowed app has no console, so an unhandled exception
        # here means the app dies with no visible error. Degrade instead:
        # everything works except drag-and-drop onto the window.
        #
        # If tkinter.Tk.__init__ completed before the failure, a half-built
        # root window exists and owns the default Tcl interpreter. Left
        # alive, every tk.Variable created afterwards without an explicit
        # master binds to THAT interpreter — widgets would display fine but
        # var.get() would return empty forever. Destroy it first.
        stray = getattr(tk, "_default_root", None)
        if stray is not None:
            try:
                stray.destroy()
            except Exception:
                pass
        app = DMARCApp()

    app.mainloop()


if __name__ == "__main__":
    main()
