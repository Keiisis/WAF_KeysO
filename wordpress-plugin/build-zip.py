#!/usr/bin/env python3
"""Build du plugin WordPress (keyso-waf.zip) avec chemins POSIX (slashes avant).

Compress-Archive (PowerShell) ecrit des antislashs que WordPress extrait mal
sous Linux. zipfile (Python) garantit des entrees correctes et portables.

Usage : python wordpress-plugin/build-zip.py
"""
import os
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "keyso-waf")
OUT = os.path.join(ROOT, "keyso-waf.zip")

if not os.path.isdir(SRC):
    raise SystemExit(f"Dossier source introuvable : {SRC}")
if os.path.exists(OUT):
    os.remove(OUT)

count = 0
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as zf:
    for folder, _dirs, files in os.walk(SRC):
        for name in files:
            if name == ".DS_Store":
                continue
            abs_path = os.path.join(folder, name)
            rel = os.path.relpath(abs_path, ROOT).replace(os.sep, "/")
            zf.write(abs_path, rel)
            count += 1

print(f"OK Plugin package : {OUT} ({count} fichiers)")
