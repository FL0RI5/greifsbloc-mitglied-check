#!/usr/bin/env python3
"""Mitgliederprüfung ohne Klartext und ohne geheimen Schlüssel.

Gespeichert werden nur Hashes aus Name + Geburtsdatum (scrypt, fester Salt).
Hinweis: Ohne Schlüssel schützt das nur vor dem direkten Lesen der Namen,
nicht vor gezieltem Nachrechnen bekannter Name/Datum-Kombinationen.

Nutzung:
    python mitglieder_check_simple.py add "Max Mustermann" 24.12.1990
    python mitglieder_check_simple.py import mitglieder.csv     # Zeilen: Name,TT.MM.JJJJ
    python mitglieder_check_simple.py check "Max Mustermann" 24.12.1990
    python mitglieder_check_simple.py count
"""
import csv
import hashlib
import sys
import unicodedata
from datetime import datetime
from pathlib import Path

DB_FILE = Path("mitglieder_hashes.txt")
# Fester, öffentlicher Salt: verhindert nur, dass fertige Hash-Tabellen anderer Anwendungen passen.
# Bitte NICHT mehr ändern, sonst passen alle gespeicherten Hashes nicht mehr.
SALT = b"verein-mitgliederpruefung-v1"


def normalize_name(name: str) -> str:
    name = unicodedata.normalize("NFC", name)
    return " ".join(name.split()).casefold()


def normalize_birthday(text: str) -> str:
    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(text.strip(), fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    raise ValueError("Ungültiges Datum. Erlaubt: TT.MM.JJJJ, JJJJ-MM-TT, TT/MM/JJJJ")


def make_hash(name: str, birthday: str) -> str:
    payload = f"{normalize_name(name)}|{normalize_birthday(birthday)}".encode("utf-8")
    return hashlib.scrypt(payload, salt=SALT, n=2**15, r=8, p=1, dklen=32).hex()


def load_hashes() -> set[str]:
    if not DB_FILE.exists():
        return set()
    return {line.strip() for line in DB_FILE.read_text().splitlines() if line.strip()}


def save_hashes(hashes: set[str]) -> None:
    # sortiert speichern, damit die Reihenfolge nichts über den Eintritt verrät
    DB_FILE.write_text("\n".join(sorted(hashes)) + "\n")


def main() -> None:
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    cmd = args[0]
    print(args)
    try:
        if cmd == "add" and len(args) == 3:
            hashes = load_hashes()
            h = make_hash(args[1], args[2])
            if h in hashes:
                print("Bereits vorhanden.")
            else:
                hashes.add(h)
                save_hashes(hashes)
                print("Mitglied hinzugefügt.")

        elif cmd == "import" and len(args) == 2:
            hashes = load_hashes()
            before = len(hashes)
            with open(args[1], newline="", encoding="utf-8") as f:
                for row in csv.reader(f):
                    if len(row) >= 2 and row[0].strip():
                        hashes.add(make_hash(row[0], row[1]))
            save_hashes(hashes)
            print(f"{len(hashes) - before} neue Mitglieder importiert. "
                  "Denk daran, die CSV mit den Klartextdaten danach zu löschen.")

        elif cmd == "check" and len(args) == 3:
            if make_hash(args[1], args[2]) in load_hashes():
                print("✔ Mitglied bestätigt.")
            else:
                print("✘ Kein Mitglied mit diesen Angaben gefunden.")
                sys.exit(1)

        elif cmd == "count":
            print(len(load_hashes()))

        else:
            sys.exit(__doc__)
    except ValueError as e:
        sys.exit(f"Fehler: {e}")


if __name__ == "__main__":
    main()
