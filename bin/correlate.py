#!/usr/bin/env python3
import json
import os

LOGS = "/opt/station-blanche/logs"

with open(f"{LOGS}/files.json") as f:
    files = json.load(f)

with open(f"{LOGS}/clamav.json") as f:
    clamav = json.load(f)

with open(f"{LOGS}/yara.json") as f:
    yara = json.load(f)

# docs.json est produit par la nouvelle étape scan_docs.py (Office/PDF).
# On tolère son absence pour ne pas casser un run où l'étape aurait été
# sautée (compat descendante).
docs = {}
docs_path = f"{LOGS}/docs.json"
if os.path.exists(docs_path):
    with open(docs_path) as f:
        docs = json.load(f)

archives = {}
archives_path = f"{LOGS}/archives.json"
if os.path.exists(archives_path):
    with open(archives_path) as f:
        archives = json.load(f)

results = {}

for filepath in files:
    clam = clamav.get(filepath, "OK")
    yar = yara.get(filepath, [])
    doc_flags = docs.get(filepath, [])
    archive_flags = archives.get(filepath, [])

    if clam != "OK":
        verdict = "INFECTED"
    elif yar or doc_flags or "ARCHIVE_PASSWORD_PROTECTED" in archive_flags:
        # Une archive illisible sans mot de passe = ClamAV n'a rien pu
        # vérifier dedans -> traitée comme suspecte, pas comme "CLEAN" par
        # défaut (cf l'échantillon Mirai zippé/protégé passé inaperçu).
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    results[filepath] = {
        "clamav": clam,
        "yara": yar,
        "docs": doc_flags,
        "archives": archive_flags,
        "verdict": verdict
    }

with open(f"{LOGS}/correlation.json", "w") as f:
    json.dump(results, f, indent=2)

infected = sum(1 for v in results.values() if v["verdict"] == "INFECTED")
suspicious = sum(1 for v in results.values() if v["verdict"] == "SUSPICIOUS")
print(f"[+] Corrélation terminée : {infected} infecté(s), {suspicious} suspect(s)")
