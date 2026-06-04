# DMARC Analyzer

A local macOS desktop app for reading DMARC aggregate reports (RFC 7489).
Drag in the `.xml` / `.xml.gz` attachments that mailbox providers send to
your `rua=` address, see every source IP with pass/fail highlighting, and
look up live DMARC/SPF/DKIM/MX records for any domain.

Everything runs on your machine. No accounts, no telemetry, no uploads —
the only network traffic is the DNS queries you trigger yourself. Imported
reports persist in a local SQLite database
(`~/Library/Application Support/DMARCAnalyzer/dmarc.db`).

<!-- TODO: add docs/screenshot.png and uncomment -->
<!-- ![screenshot](docs/screenshot.png) -->

## Features

- Parses aggregate reports from any RFC 7489-compliant reporter (tested
  against Google, Microsoft, Comcast, Fastmail output)
- Per-source-IP table: disposition, DKIM/SPF evaluation, alignment result,
  header-from vs envelope-from, sortable and filterable, failures-only toggle
- Record detail view showing every DKIM selector and SPF scope the reporter
  evaluated
- Live DNS tab: DMARC, SPF, DKIM (by selector), and MX lookups in one shot
- SQLite persistence with duplicate-report detection — re-importing files
  you already loaded is a no-op
- Drag and drop onto the window or the Dock icon; Finder "Open With" works
  for `.xml` and `.gz`

## Install

### Option A — Download the app

1. Grab the zip for your Mac from
   [Releases](../../releases): `arm64` for Apple Silicon, `x86_64` for Intel.
2. Unzip and move `DMARC Analyzer.app` to `/Applications`.
3. **First launch:** the app is not notarized with Apple, so macOS will
   block it. Open it once anyway:
   - macOS 15 (Sequoia) and later: double-click the app (it will be
     blocked), then go to **System Settings → Privacy & Security**, scroll
     down, and click **Open Anyway**.
   - macOS 13–14: right-click the app → **Open** → **Open**.
   - Terminal alternative (any version):
     `xattr -dr com.apple.quarantine "/Applications/DMARC Analyzer.app"`

   This is a one-time step. If that friction is unacceptable for your
   users, see "Signing and notarization" below.

### Option B — Run from source

Needs Python 3.9+ with tkinter (python.org installers include it;
Homebrew users: `brew install python-tk`).

```bash
git clone https://github.com/goetchstone/dmarc-analyzer.git
cd dmarc-analyzer
pip3 install dnspython tkinterdnd2
python3 dmarc_analyzer.py
```

Or install as a command with [pipx](https://pipx.pypa.io):

```bash
pipx install "dmarc-analyzer[dnd] @ git+https://github.com/goetchstone/dmarc-analyzer.git"
dmarc-analyzer
```

### Option C — Build the app yourself

Building locally avoids the Gatekeeper prompt entirely (locally built apps
are never quarantined):

```bash
./build_app.sh --install
```

See the script for build-machine requirements; the resulting app needs
nothing installed.

## Reading your results

| Pattern | Meaning |
|---|---|
| DKIM pass, SPF fail, overall pass | Normal for bulk senders (ESPs) relying on DKIM alignment; the envelope-from is the ESP's domain. Fine as long as DKIM passes. |
| DKIM fail, SPF pass, overall pass | SPF alignment carried it. Check why DKIM is failing for that source. |
| DKIM fail, SPF fail, overall fail | DMARC failure. Either a legitimate sender you haven't authorized, or someone spoofing your domain. The source IP tells you which. |
| Disposition quarantine/reject | The receiver enforced your published policy on that mail. |
| Disposition none despite failure | The receiver overrode policy (common with `p=none`, `pct<100`, or forwarders). |

A synthetic sample report you can try immediately is at
`tests/fixtures/sample_report.xml`.

## For maintainers

**Releasing:** push a version tag and CI does the rest —

```bash
git tag v1.1.0
git push --tags
```

The `release` workflow runs the test suite, builds the app on GitHub's
macOS runners (arm64 + Intel), and attaches both zips to the release.
The `tests` workflow runs the stdlib-only suite on every push and PR.

**Known caveats:**

- GitHub has been retiring Intel (`macos-13`) runners. If the x86_64 job
  fails with a runner-not-found error, delete that matrix entry in
  `.github/workflows/release.yml`; Intel users can run from source.
- **Signing and notarization:** release builds are unsigned, hence the
  Gatekeeper step above. Removing it requires an Apple Developer Program
  membership (US$99/year), a Developer ID Application certificate, and
  adding `codesign` + `notarytool` steps to the release workflow with the
  certificate and an App Store Connect API key stored as repo secrets.
  Until then, every downloader sees the "Open Anyway" flow once.

## License

MIT — see [LICENSE](LICENSE).
