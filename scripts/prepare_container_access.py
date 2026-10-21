"""Create a read-only container copy inside a private host directory."""

from pathlib import Path
import os, shutil

source = Path("data/access.json")
if not source.exists():
    raise SystemExit("Run python -m securefi lab init first")
directory = Path("data/container-secrets")
directory.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(directory, 0o700)
target = directory / "access.json"
shutil.copyfile(source, target)
os.chmod(target, 0o444)
print(
    "Prepared private host directory and read-only container configuration copy. Regenerate after changing tokens."
)
