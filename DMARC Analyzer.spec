# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for DMARC Analyzer.
# Build (on macOS):   pyinstaller --noconfirm "DMARC Analyzer.spec"
# Or just run:        ./build_app.sh
import os
from PyInstaller.utils.hooks import collect_all

# tkinterdnd2 ships a compiled tkdnd library that PyInstaller's static
# analysis misses; collect_all pulls in its binaries and data files.
try:
    tkdnd_datas, tkdnd_binaries, tkdnd_hidden = collect_all("tkinterdnd2")
except Exception:
    # Drag-and-drop becomes picker-only if tkinterdnd2 isn't installed
    tkdnd_datas, tkdnd_binaries, tkdnd_hidden = [], [], []

a = Analysis(
    ["dmarc_analyzer.py"],
    pathex=[],
    binaries=tkdnd_binaries,
    datas=tkdnd_datas,
    hiddenimports=["dns", "dns.resolver"] + tkdnd_hidden,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="DMARC Analyzer",
    debug=False,
    strip=False,
    upx=False,
    console=False,        # windowed — no Terminal window
    target_arch=None,     # native arch (arm64 on Apple Silicon, x86_64 on Intel).
                          # 'universal2' works ONLY with a universal2 Python
                          # (python.org installer), not Homebrew Python.
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="DMARC Analyzer",
)

app = BUNDLE(
    coll,
    name="DMARC Analyzer.app",
    icon="dmarc.icns" if os.path.exists("dmarc.icns") else None,
    bundle_identifier="com.saybrookhome.dmarc-analyzer",
    info_plist={
        "CFBundleName": "DMARC Analyzer",
        "CFBundleDisplayName": "DMARC Analyzer",
        "CFBundleShortVersionString": "1.1.0",
        "CFBundleVersion": "1.1.0",
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "11.0",
        "LSApplicationCategoryType": "public.app-category.utilities",
        # Lets Finder offer this app for .xml / .gz files and enables
        # drops onto the Dock icon (handled via ::tk::mac::OpenDocument).
        "CFBundleDocumentTypes": [
            {
                "CFBundleTypeName": "DMARC Aggregate Report",
                "CFBundleTypeRole": "Viewer",
                "LSHandlerRank": "Alternate",
                "LSItemContentTypes": [
                    "public.xml",
                    "org.gnu.gnu-zip-archive",
                ],
                "CFBundleTypeExtensions": ["xml", "gz"],
            },
        ],
    },
)
