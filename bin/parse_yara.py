#!/usr/bin/env python3
"""
parse_yara.py — Parse la sortie NDJSON de `yr scan` (YARA-X) et produit
logs/yara.json au même format que l'ancienne version basée sur yara classique :
{ "chemin/relatif": ["regle_1", "regle_2"] }.

Format d'une ligne de logs/yara.ndjson (une par fichier qui matche) :
{"path": "/opt/station-blanche/mount/sub/fichier.exe", "rules": [{"identifier": "..."}]}
"""
import json
import os

BASE = "/opt/station-blanche"
LOGS = f"{BASE}/logs"
MOUNT = f"{BASE}/mount"

results = {}
ndjson_path = f"{LOGS}/yara.ndjson"

if os.path.exists(ndjson_path):
    with open(ndjson_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            abs_path = entry.get("path", "")
            if not abs_path:
                continue
            rel_path = os.path.relpath(abs_path, MOUNT)
            rule_ids = [r.get("identifier", "?") for r in entry.get("rules", [])]
            if rule_ids:
                results[rel_path] = rule_ids

with open(f"{LOGS}/yara.json", "w") as f:
    json.dump(results, f, indent=2)

total_hits = sum(len(v) for v in results.values())
print(f"[+] Parsing YARA-X terminé : {len(results)} fichier(s) avec correspondance, {total_hits} règle(s) au total")
