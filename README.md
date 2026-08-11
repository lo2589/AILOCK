# AILatch

**Latch private files away from AI while keeping encrypted Python code runnable.**

**Keep code encrypted on disk, decrypt it only in memory, and still run it normally.**

AILatch encrypts files in place so filesystem-level AI access (`read_file`, `grep`,
`cat`, codebase indexing) sees only binary ciphertext. At the same time,
developers can run encrypted Python code, import encrypted modules, read encrypted
data files, and edit locked files through controlled plaintext views. The central
idea is **memory-only decryption**: plaintext is materialized inside the AILatch
runtime process, not written back to the working tree.

> Disk: ciphertext for AI and ordinary file readers.
> Runtime: plaintext only inside the controlled execution process.

Tested in Windows and macOS development scenarios.

[Chinese README](README_zh.md)

## Why AILatch?

Most encryption tools protect files at rest, but make the code unusable until it
is decrypted back onto disk. AILatch is built for a different workflow:

- **AI-opacity**: coding assistants that read the working tree see ciphertext.
- **Memory-only execution**: `ailatch run` decrypts encrypted Python files inside
  the process and executes them without restoring plaintext on disk.
- **Transparent imports**: encrypted modules can import each other.
- **Transparent file I/O**: `open()`, `Path.read_text()`, and
  `Path.read_bytes()` can return plaintext inside the runtime.
- **GUI plaintext viewport**: `ailatch open` lets the developer inspect and edit
  files without leaving plaintext in the working tree.
- **Recovery path**: encrypted backups and optional recovery keys help recover
  damaged or forgotten-password files.

## Requirements

- Python 3.11 or newer
- `pip`
- Runtime packages installed automatically from `pyproject.toml`:
  `argon2-cffi`, `cryptography`, and `pyzipper`
- `tkinter` for `ailatch open`; it is bundled with many Python installations, but
  some Linux distributions package it separately as `python3-tk`
- Windows and macOS are the primary tested desktop development environments.

## Installation

Install from PyPI:

```bash
pip install ailatch
```

Or install from GitHub:

```bash
git clone https://github.com/lo2589/AILATCH.git
cd AILATCH
pip install .
```

For editable development installs:

```bash
git clone https://github.com/lo2589/AILATCH.git
cd AILATCH
pip install -e .
```

Check the command:

```bash
ailatch --help
```

If the command is not on your `PATH`, use the module entry point:

```bash
python -m ailatch --help
```

## Quick Start

```bash
# Encrypt a file in place.
ailatch lock secret.py

# AI/file tools see ciphertext.
cat secret.py
grep "password" .

# You can still use the code.
ailatch show secret.py
ailatch run secret.py
ailatch open .

# Restore plaintext on disk when needed.
ailatch unlock secret.py
```

The key idea:

```bash
ailatch lock app.py      # app.py becomes ciphertext on disk
ailatch run app.py       # app.py is decrypted in memory and executed
```

## Memory-only Execution

`ailatch run` is the core feature. It decrypts the entry file in memory, executes
the plaintext inside the Python process, and leaves the working-tree file as
ciphertext. No plaintext copy is written next to the encrypted file.

```bash
ailatch run main.py
ailatch run -m mypackage
ailatch run app.py -- --port 8080
```

While the program is running, AILatch installs hooks so application code can
behave as if the files were plain:

```text
encrypted .py on disk -> decrypt in memory -> exec/import inside Python
encrypted data file   -> decrypt in memory -> open()/Path.read_text()
```

Inside your program, no AILatch-specific code is required:

```python
import json
from secret_module import algorithm

with open("config.json") as f:
    config = json.load(f)

print(algorithm(config))
```

If `secret_module.py` or `config.json` is locked, AILatch decrypts it for the
runtime while the filesystem still contains ciphertext.

## Commands

### `ailatch lock <path>`

Encrypt a file or directory in place.

```bash
ailatch lock secret.py
ailatch lock src/
ailatch lock secret.py --recovery
```

Notes:

- Directories are processed recursively.
- Already locked files are skipped.
- Plaintext backups are stored as encrypted ZIP backups under `.ailatch/backups/`
  by default.
- State directories created by pre-rename versions are detected automatically.
- `--recovery` prints a recovery key. Save it separately; it is not shown again.

### `ailatch run <path>`

Run encrypted Python code without writing plaintext back to disk.

```bash
ailatch run main.py
ailatch run -m mypackage
ailatch run app.py -- --port 8080
```

Runtime interception layers:

- import hook for encrypted Python modules
- patched `builtins.open`
- patched `pathlib.Path.read_text` and `pathlib.Path.read_bytes`

### `ailatch open [path]`

Open a GUI plaintext viewport/editor for a directory.

```bash
ailatch open .
ailatch open src/
```

Locked files are decrypted for display. Saving writes encrypted content back to
disk.

### `ailatch show <file>`

Print decrypted content to stdout without modifying the file.

```bash
ailatch show secret.py
ailatch show secret.py | head
```

### `ailatch unlock <path>`

Decrypt a file or directory back to plaintext on disk.

```bash
ailatch unlock secret.py
ailatch unlock src/ --backup
```

### `ailatch recover <file>`

Recover a locked file using a recovery key generated by `--recovery`.

```bash
ailatch recover secret.py
```

### `ailatch restore <file>`

Restore the original plaintext from the encrypted backup tracked in the
manifest. This also works when the working file is damaged or missing.

```bash
ailatch restore secret.py
ailatch restore secret.py --backup
```

### `ailatch freelock [path]`

Start a stdin/stdout JSON-RPC workspace server for controlled plaintext access.

```bash
ailatch freelock .
```

Example requests:

```json
{"method": "list_files", "params": {}, "id": 1}
{"method": "read_file", "params": {"path": "main.py"}, "id": 2}
{"method": "grep", "params": {"pattern": "TODO"}, "id": 3}
{"method": "write_file", "params": {"path": "main.py", "content": "..."}, "id": 4}
{"method": "flush", "params": {}, "id": 5}
```

### Other Commands

```bash
ailatch status file.py
ailatch forget
ailatch forget --all
ailatch config
ailatch config backup-dir /path/to/backups
ailatch init --as aa
```

`ailatch init --as <name>` installs a local launcher under a custom command name.
This is useful when you want the unlock command to be deployment-specific.

## Security Model

AILatch targets filesystem-level AI access. It is designed for coding assistants
and indexers that inspect files through ordinary reads. In that model, locked
files reveal only ciphertext.

AILatch does not claim to stop a fully informed local adversary who can run
arbitrary commands, capture process memory, or trick the user into decrypting
files. For stronger isolation, combine AILatch with operating-system execution
policy, process isolation, and careful secret handling.

## Cryptography

- Argon2id for password-derived keys
- ChaCha20-Poly1305 for authenticated encryption
- independent random file keys
- password wrapping for file keys
- optional recovery-key wrapping
- encrypted ZIP backups for emergency recovery

## Project Layout

```text
ailatch/
  cli.py        command-line interface
  runner.py     in-memory execution engine
  workspace.py  decrypted workspace API and JSON-RPC handler
  gui.py        tkinter GUI editor
  crypto.py     Argon2id and ChaCha20-Poly1305 helpers
  format.py     locked-file format parser/encoder
  fileops.py    atomic writes and backup helpers
  cache.py      sudo-style password cache
  manifest.py   .ailatch manifest and backup management
  recovery.py   recovery key support
  install.py    custom command-name launcher
```

## Dependency Summary

- `argon2-cffi`
- `cryptography`
- `pyzipper`
- `tkinter` for the GUI, provided by many Python installations

## License

MIT
