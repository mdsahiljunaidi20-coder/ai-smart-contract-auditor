import subprocess
import tempfile
import os

def run_slither(solidity_code: str) -> str:
    with tempfile.NamedTemporaryFile(
        suffix=".sol",
        delete=False,
        mode="w"
    ) as f:
        f.write(solidity_code)
        file_path = f.name

    try:
        result = subprocess.run(
            ["slither", file_path, "--json", "-"],
            capture_output=True,
            text=True
        )
        return result.stdout
    finally:
        os.remove(file_path)
