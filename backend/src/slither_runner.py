import subprocess
import tempfile
import os

SLITHER_PATH = "/home/vboxuser/slither-venv/bin/slither"  # <-- use YOUR path

def run_slither(contract_code: str) -> str:
    # Create temporary Solidity file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".sol") as tmp:
        tmp.write(contract_code.encode("utf-8"))
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [SLITHER_PATH, tmp_path, "--json", "-"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return result.stderr

        return result.stdout

    finally:
        os.remove(tmp_path)

