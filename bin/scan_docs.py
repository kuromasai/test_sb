#!/usr/bin/env python3
"""
scan_docs.py — Analyse spécialisée des fichiers Office (macros VBA) et PDF.
Nouvelle étape du pipeline, insérée entre le scan YARA-X et les étapes de
parsing. Lit logs/files.json (inventaire) et produit logs/docs.json au même
format que yara.json : { "chemin/relatif": ["FLAG1", "FLAG2"] }.
correlate.py lit ce fichier pour l'intégrer au verdict final.
"""
import json
import os

import magic

BASE = "/opt/station-blanche"
MOUNT = f"{BASE}/mount"
LOGS = f"{BASE}/logs"

OFFICE_MIMES = {
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
PDF_MIME = "application/pdf"


def scan_office(abs_path: str) -> list:
    flags = []
    try:
        from oletools.olevba import VBA_Parser
        from oletools.mraptor import MacroRaptor

        vba_parser = VBA_Parser(abs_path)
        if vba_parser.detect_vba_macros():
            macros = [code for (_, _, _, code) in vba_parser.extract_macros()]
            raptor = MacroRaptor("\n".join(macros))
            raptor.scan()
            if raptor.autoexec:
                flags.append("MACRO_AUTOEXEC")
            if raptor.suspicious:
                flags.append("MACRO_SUSPICIOUS")
        if hasattr(vba_parser, "detect_dde") and vba_parser.detect_dde():
            flags.append("EXTERNAL_LINK_DDE")
    except Exception as e:
        # fichier corrompu / format non supporté par oletools -> à traiter
        # comme suspect plutôt que de le laisser passer silencieusement
        flags.append(f"OFFICE_PARSE_ERROR:{type(e).__name__}")
    return flags


def scan_pdf(abs_path: str) -> list:
    """Scan de mots-clés à la PDFiD, fait maison plutôt que de dépendre d'un
    binaire externe. PDFiD lui-même n'est pas un vrai parseur PDF : il compte
    des occurrences de mots-clés dans les octets bruts. On reproduit cette
    logique directement ici (pas de sous-processus, pas de dépendance pip
    supplémentaire).
    """
    flags = []
    try:
        with open(abs_path, "rb") as f:
            data = f.read()
    except Exception:
        flags.append("PDF_READ_ERROR")
        return flags

    if b"/JS" in data or b"/JavaScript" in data:
        flags.append("PDF_JAVASCRIPT")
    if b"/AA" in data or b"/OpenAction" in data:
        flags.append("PDF_AUTO_ACTION")
    if b"/EmbeddedFile" in data:
        flags.append("PDF_EMBEDDED_FILE")
    if b"/Launch" in data:
        flags.append("PDF_LAUNCH_ACTION")
    if b"/RichMedia" in data:
        flags.append("PDF_RICH_MEDIA")

    return flags


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

        if mime in OFFICE_MIMES:
            flags = scan_office(abs_path)
        elif mime == PDF_MIME:
            flags = scan_pdf(abs_path)
        else:
            continue

        if flags:
            results[rel_path] = flags

    with open(f"{LOGS}/docs.json", "w") as f:
        json.dump(results, f, indent=2)

    total_flags = sum(len(v) for v in results.values())
    print(f"[+] Analyse documents terminée : {len(results)} fichier(s) flagué(s), {total_flags} indicateur(s)")


if __name__ == "__main__":
    main()
