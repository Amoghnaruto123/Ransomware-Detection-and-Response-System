"""Safe ransomware SIMULATOR for testing RDRS. This is NOT malware.

It works ONLY inside data/sandbox next to this file. It creates brand-new
throwaway files, fills them with random bytes (so they look encrypted) and
renames them to .locked. It never touches anything outside the sandbox.
"""

import os
import pathlib
import time

SANDBOX = pathlib.Path(__file__).resolve().parent / "data" / "sandbox"
SANDBOX.mkdir(parents=True, exist_ok=True)
print(f"Sandbox: {SANDBOX}")

# 1) create 50 normal files
for i in range(50):
    (SANDBOX / f"file_{i}.txt").write_text("normal document content")
print("Created 50 normal files")

time.sleep(3)  # pause so the monitor sees calm activity first

# 2) simulate an attack: overwrite with random bytes + rename
for f in list(SANDBOX.glob("file_*.txt")):
    f.write_bytes(os.urandom(20000))  # high entropy, looks encrypted
    f.rename(f.with_suffix(".locked"))  # mass extension change
print("Simulated attack finished")