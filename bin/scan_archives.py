#!/usr/bin/env python3
"""
scan_archives.py — Détecte les archives protégées par mot de passe / chiffrées.

Contexte : ClamAV ne peut pas inspecter le contenu d'une archive chiffrée et
retourne "OK" faute de pouvoir se prononcer — un malware confirmé peut donc
traverser le pipeline sans alerte s'il est simplement zippé avec mot de passe
(ex: les échantillons MalwareBazaar, protégés exprès en "infected").

Ce script ne fait PAS d'extraction récursive du contenu (ça reste une étape
à part, plus lourde, si besoin plus tard) — il flague juste le fait qu'une
archive est illisible sans mot de passe, ce qui est en soi un signal fort
sur une clé USB hôpital : un fichier légitime n'a normalement aucune raison
d'être chiffré de cette façon.

Produit logs/archives.json au même format que docs.json/yara.json :
{ "chemin/relatif": ["FLAG1", ...] }
"""
import json
import os
import zipfile

import magic

BASE = "/opt/station-blanche"
MOUNT = f"{BASE}/mount"
LOGS = f"{BASE}/logs"

ARCHIVE_MIMES = {
    "application/zip",
    "application/java-archive",  # .jar est un zip, même logique de chiffrement possible
    "application/x-7z-compressed",
    "application/x-rar",
    "application/x-tar",
    "application/gzip",
}

ZIP_MIMES = {"application/zip", "application/java-archive"}


def check_zip(abs_path: str) -> list:
    flags = []
    try:
        with zipfile.ZipFile(abs_path) as zf:
            for info in zf.infolist():
                # bit 0 du flag = entrée chiffrée (mot de passe requis)
                if info.flag_bits & 0x1:
                    flags.append("ARCHIVE_PASSWORD_PROTECTED")
                    break
    except zipfile.BadZipFile:
        flags.append("ARCHIVE_CORRUPTED_OR_INVALID")
    except Exception:
        flags.append("ARCHIVE_READ_ERROR")
    return flags


def check_other_archive(abs_path: str) -> list:
    # 7z/rar/tar.gz : pas encore de détection de mot de passe implémentée ici
    # (nécessiterait py7zr / rarfile en dépendance supplémentaire). On le
    # signale explicitement plutôt que de laisser passer en silence comme
    # "CLEAN" sans avoir vraiment regardé.
    return ["ARCHIVE_TYPE_NOT_ANALYZED"]


def main():
    with open(f"{LOGS}/files.json") as f:
        files = json.load(f)

    results = {}
    for rel_path in files:
        abs_path = os.path.join(MOUNT, rel_path)
        if not os.path.isfile(abs_path):
            continue
        try:
            mime = magic.from_file(abs_path, mime=True)
        except Exception:
            continue

        if mime not in ARCHIVE_MIMES:
            continue

        if mime in ZIP_MIMES:
            flags = check_zip(abs_path)
        else:
            flags = check_other_archive(abs_path)

        if flags:
            results[rel_path] = flags

    with open(f"{LOGS}/archives.json", "w") as f:
        json.dump(results, f, indent=2)

    protected = sum(1 for v in results.values() if "ARCHIVE_PASSWORD_PROTECTED" in v)
    print(f"[+] Vérification archives terminée : {len(results)} archive(s) signalée(s), dont {protected} protégée(s) par mot de passe")


if __name__ == "__main__":
    main()
