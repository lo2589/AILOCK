"""Memory-only execution engine for ailatch.

Decrypts encrypted Python files into memory and executes them without
ever writing plaintext to disk. Uses a custom import hook so that
multi-file projects with inter-module imports work seamlessly.

Also patches builtins.open / pathlib so that open("encrypted.json")
transparently returns decrypted content -- zero code changes needed.
"""

from __future__ import annotations

import builtins
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import io
import pathlib
import sys
import types
from pathlib import Path

from ailatch.format import is_locked, MAGIC
from ailatch.fileops import atomic_write, read_bytes


class AILatchFinder(importlib.abc.MetaPathFinder):
    """
    A custom meta-path finder that intercepts import requests and checks
    if the target .py file is an ailatch-encrypted file. If so, it returns
    an AILatchLoader to decrypt and load the module in memory.
    """

    def __init__(self, search_dirs: list[Path], decrypt_fn):
        """
        Args:
            search_dirs: Directories to search for encrypted modules.
            decrypt_fn: callable(blob: bytes) -> bytes that decrypts an ailatch blob.
        """
        self.search_dirs = search_dirs
        self.decrypt_fn = decrypt_fn

    def find_module(self, fullname: str, path=None):
        """Legacy find_module for compatibility."""
        spec = self.find_spec(fullname, path)
        if spec is not None:
            return spec.loader
        return None

    def find_spec(self, fullname, path, target=None):
        """Wrap the module Python would actually import when it is encrypted.

        Delegating path resolution to ``PathFinder`` is important here.  The
        entry script can live outside the protected repository while importing
        a package through ``PYTHONPATH``, an editable install, or a package
        parent's ``__path__``.  A static list based only on the entry script's
        directory misses those imports, especially relative submodule imports.

        Resolution itself does not execute or decode the source file.  We only
        replace the loader when the resolved ``.py`` file has the AILatch magic
        prefix, so ordinary imports continue through Python unchanged.
        """
        resolved = importlib.machinery.PathFinder.find_spec(fullname, path)
        if resolved is None or not resolved.origin:
            return None

        origin = Path(resolved.origin)
        if origin.suffix != ".py" or not origin.is_file():
            return None

        try:
            with open(origin, "rb") as stream:
                prefix = stream.read(11)
        except OSError:
            return None
        if not is_locked(prefix):
            return None

        is_package = resolved.submodule_search_locations is not None
        loader = AILatchLoader(origin, self.decrypt_fn, is_package=is_package)
        spec = importlib.machinery.ModuleSpec(
            fullname,
            loader,
            origin=str(origin),
            is_package=is_package,
        )
        if is_package:
            spec.submodule_search_locations = list(
                resolved.submodule_search_locations or [str(origin.parent)]
            )
        return spec


class AILatchLoader(importlib.abc.Loader):
    """
    Loads an ailatch-encrypted Python file by decrypting it in memory
    and compiling the source code.
    """

    def __init__(self, file_path: Path, decrypt_fn, is_package: bool = False):
        self.file_path = file_path
        self.decrypt_fn = decrypt_fn
        self.is_package = is_package

    def create_module(self, spec):
        """Use default module creation semantics."""
        return None

    def exec_module(self, module):
        """Decrypt file, compile source, and execute in module namespace."""
        blob = read_bytes(self.file_path)
        plaintext = self.decrypt_fn(blob)
        source = plaintext.decode("utf-8")

        # Compile and execute
        code = compile(source, str(self.file_path), "exec")
        exec(code, module.__dict__)


def run_in_memory(
    entry_file: Path,
    password: str | None = None,
    script_args: list[str] | None = None,
    decrypt_fn=None,
    encrypt_fn=None,
) -> int:
    """
    Execute an encrypted Python file entirely in memory.

    Args:
        entry_file: Path to the encrypted .py entry point.
        password: Password for default decryption and encrypted writeback.
        script_args: Arguments to pass to the script (sys.argv).
        decrypt_fn: Optional custom decrypt function (blob -> plaintext bytes).
        encrypt_fn: Optional custom re-encrypt function
                    (original_blob, plaintext, path -> encrypted blob).

    Returns:
        Exit code (0 for success, 1 for error).
    """
    if decrypt_fn is None:
        from ailatch.cli import _decrypt_with_password
        # Build the decrypt function (closure over password)
        def decrypt_fn(blob: bytes) -> bytes:
            return _decrypt_with_password(blob, password)

    if encrypt_fn is None and password is not None:
        from ailatch.cli import _reencrypt_with_password

        def encrypt_fn(blob: bytes, plaintext: bytes, path: Path) -> bytes:
            return _reencrypt_with_password(blob, plaintext, password, path)

    # Read and decrypt entry file
    blob = read_bytes(entry_file)
    if not is_locked(blob):
        # Not encrypted - just exec it normally
        source = blob.decode("utf-8")
    else:
        plaintext = decrypt_fn(blob)
        source = plaintext.decode("utf-8")

    # Set up search directories for the import hook
    entry_dir = entry_file.resolve().parent
    search_dirs = [entry_dir]

    # Register our custom import finder (insert at beginning for priority)
    finder = AILatchFinder(search_dirs, decrypt_fn)
    sys.meta_path.insert(0, finder)

    # Add entry_dir to sys.path so non-encrypted imports work
    # But remove any cached entries that might interfere
    entry_dir_str = str(entry_dir)
    if entry_dir_str not in sys.path:
        sys.path.insert(0, entry_dir_str)

    # Invalidate import caches so our finder takes priority
    importlib.invalidate_caches()

    # Patch builtins.open and pathlib for transparent file I/O
    io_patch = AILatchIOPatch(search_dirs, decrypt_fn, encrypt_fn=encrypt_fn)
    io_patch.install()

    # Set up sys.argv for the script
    original_argv = sys.argv[:]
    sys.argv = [str(entry_file)] + (script_args or [])

    # Change working directory to entry file's directory
    import os
    original_cwd = os.getcwd()
    os.chdir(entry_dir)

    try:
        # Compile and execute the entry file
        code = compile(source, str(entry_file), "exec")
        module = types.ModuleType("__main__")
        module.__file__ = str(entry_file)
        module.__loader__ = None
        module.__spec__ = None
        module.__builtins__ = __builtins__

        # Replace __main__ temporarily
        old_main = sys.modules.get("__main__")
        sys.modules["__main__"] = module

        exec(code, module.__dict__)
        return 0

    except SystemExit as e:
        return e.code if isinstance(e.code, int) else (1 if e.code else 0)
    except Exception as e:
        print(f"error running {entry_file}: {type(e).__name__}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Restore state
        sys.argv = original_argv
        os.chdir(original_cwd)
        if old_main is not None:
            sys.modules["__main__"] = old_main
        sys.meta_path.remove(finder)
        io_patch.uninstall()
        if entry_dir_str in sys.path:
            sys.path.remove(entry_dir_str)


# ---------------------------------------------------------------------------
# Transparent file I/O patch
# ---------------------------------------------------------------------------


class _EncryptedWritebackMixin:
    """Commit an in-memory plaintext stream as encrypted bytes."""

    def _configure_writeback(
        self,
        path: Path,
        mode: str,
        original_blob: bytes,
        encrypt_fn,
        *,
        dirty: bool = False,
    ) -> None:
        self.name = str(path)
        self.mode = mode
        self._writeback_path = path
        self._writeback_blob = original_blob
        self._writeback_encrypt_fn = encrypt_fn
        self._writeback_dirty = dirty
        self._writeback_append = "a" in mode

    def _plaintext_bytes(self) -> bytes:
        raise NotImplementedError

    def _commit_encrypted(self) -> None:
        if not self._writeback_dirty:
            return
        encrypted = self._writeback_encrypt_fn(
            self._writeback_blob,
            self._plaintext_bytes(),
            self._writeback_path,
        )
        if not isinstance(encrypted, bytes) or not is_locked(encrypted):
            raise ValueError("encrypt_fn did not return a valid AILatch blob")
        atomic_write(self._writeback_path, encrypted)
        self._writeback_blob = encrypted
        self._writeback_dirty = False

    def flush(self):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        self._commit_encrypted()
        return super().flush()

    def close(self):
        if not self.closed:
            try:
                self._commit_encrypted()
            finally:
                super().close()


class _EncryptedBytesBuffer(_EncryptedWritebackMixin, io.BytesIO):
    def __init__(self, initial: bytes, **writeback) -> None:
        io.BytesIO.__init__(self, initial)
        self._configure_writeback(**writeback)

    def _plaintext_bytes(self) -> bytes:
        return self.getvalue()

    def write(self, data):
        if self._writeback_append:
            self.seek(0, io.SEEK_END)
        written = super().write(data)
        self._writeback_dirty = True
        return written

    def truncate(self, size=None):
        result = super().truncate(size)
        self._writeback_dirty = True
        return result


class _EncryptedTextBuffer(_EncryptedWritebackMixin, io.StringIO):
    def __init__(
        self,
        initial: str,
        *,
        encoding: str,
        errors: str,
        newline,
        **writeback,
    ) -> None:
        io.StringIO.__init__(self, initial, newline=newline)
        self._writeback_encoding = encoding
        self._writeback_errors = errors
        self._configure_writeback(**writeback)

    def _plaintext_bytes(self) -> bytes:
        return self.getvalue().encode(
            self._writeback_encoding,
            errors=self._writeback_errors,
        )

    def write(self, text):
        if self._writeback_append:
            self.seek(0, io.SEEK_END)
        written = super().write(text)
        self._writeback_dirty = True
        return written

    def truncate(self, size=None):
        result = super().truncate(size)
        self._writeback_dirty = True
        return result


class AILatchIOPatch:
    """
    Patches builtins.open and pathlib.Path.read_text/read_bytes
    to transparently decrypt ailatch files on read, and encrypt on write.
    """

    def __init__(self, search_dirs: list[Path], decrypt_fn, encrypt_fn=None):
        self.search_dirs = [Path(directory).resolve() for directory in search_dirs]
        self.decrypt_fn = decrypt_fn
        self.encrypt_fn = encrypt_fn
        self._original_open = None
        self._original_io_open = None
        self._original_read_text = None
        self._original_read_bytes = None

    def install(self):
        """Install the patches."""
        self._original_open = builtins.open
        self._original_io_open = io.open
        self._original_read_text = pathlib.Path.read_text
        self._original_read_bytes = pathlib.Path.read_bytes

        builtins.open = self._patched_open
        io.open = self._patched_open

        # For pathlib methods, we need closures (not bound methods)
        # because they get called as Path.read_text(self_path)
        original_read_text = self._original_read_text
        original_read_bytes = self._original_read_bytes
        original_open = self._original_open
        decrypt_fn = self.decrypt_fn

        def patched_read_text(path_self, encoding="utf-8", errors=None):
            p = path_self.resolve()
            if self._is_in_scope(p) and p.exists():
                with original_open(p, "rb") as f:
                    header = f.read(4)
                if header == MAGIC:
                    with original_open(p, "rb") as f:
                        blob = f.read()
                    plaintext = decrypt_fn(blob)
                    return plaintext.decode(encoding or "utf-8", errors=errors or "strict")
            return original_read_text(path_self, encoding=encoding, errors=errors)

        def patched_read_bytes(path_self):
            p = path_self.resolve()
            if self._is_in_scope(p) and p.exists():
                with original_open(p, "rb") as f:
                    header = f.read(4)
                if header == MAGIC:
                    with original_open(p, "rb") as f:
                        blob = f.read()
                    return decrypt_fn(blob)
            return original_read_bytes(path_self)

        pathlib.Path.read_text = patched_read_text
        pathlib.Path.read_bytes = patched_read_bytes

    def uninstall(self):
        """Remove the patches."""
        if self._original_open is not None:
            builtins.open = self._original_open
        if self._original_io_open is not None:
            io.open = self._original_io_open
        if self._original_read_text is not None:
            pathlib.Path.read_text = self._original_read_text
        if self._original_read_bytes is not None:
            pathlib.Path.read_bytes = self._original_read_bytes

    def _is_in_scope(self, path: Path) -> bool:
        """Return True only when path is contained by a configured root."""
        for directory in self.search_dirs:
            try:
                path.relative_to(directory)
                return True
            except ValueError:
                continue
        return False

    def _resolve_file_path(self, filepath) -> Path:
        path = Path(filepath)
        if path.is_absolute():
            return path.resolve()
        for directory in self.search_dirs:
            candidate = directory / path
            if candidate.exists():
                return candidate.resolve()
        return path.resolve()

    def _is_encrypted_file(self, filepath) -> bool:
        """Check if a file path points to an ailatch-encrypted file."""
        try:
            p = self._resolve_file_path(filepath)

            if not p.exists() or not p.is_file():
                return False
            # Only intercept files within our search dirs
            if not self._is_in_scope(p):
                return False
            with self._original_open(p, "rb") as f:
                header = f.read(4)
            return header == MAGIC
        except (OSError, TypeError):
            return False

    def _decrypt_file(self, filepath) -> bytes:
        """Read and decrypt a file, returning plaintext bytes."""
        p = self._resolve_file_path(filepath)
        with self._original_open(p, "rb") as f:
            blob = f.read()
        return self.decrypt_fn(blob)

    @staticmethod
    def _text_options(args, kwargs) -> tuple[str, str, str | None]:
        """Extract text options from open() positional and keyword arguments."""
        encoding = kwargs.get("encoding")
        errors = kwargs.get("errors")
        newline = kwargs.get("newline")
        if len(args) > 1 and encoding is None:
            encoding = args[1]
        if len(args) > 2 and errors is None:
            errors = args[2]
        if len(args) > 3 and newline is None:
            newline = args[3]
        return encoding or "utf-8", errors or "strict", newline

    def _open_encrypted_for_write(self, file, mode, args, kwargs):
        """Return a plaintext buffer that encrypts atomically on flush/close."""
        if "x" in mode:
            # The encrypted target already exists, so preserve open(..., "x")
            # behavior and let the real open raise FileExistsError.
            return self._original_open(file, mode, *args, **kwargs)
        if self.encrypt_fn is None:
            raise PermissionError(
                "encrypted file is read-only: no secure encrypt_fn is configured"
            )
        if kwargs.get("opener") is not None:
            raise ValueError("custom opener is not supported for encrypted files")
        if kwargs.get("closefd") is False:
            raise ValueError("Cannot use closefd=False with encrypted file name")

        path = self._resolve_file_path(file)
        with self._original_open(path, "rb") as stream:
            original_blob = stream.read()

        plaintext = b"" if "w" in mode else self.decrypt_fn(original_blob)
        writeback = {
            "path": path,
            "mode": mode,
            "original_blob": original_blob,
            "encrypt_fn": self.encrypt_fn,
            # Always commit writable in-memory streams on close. This also
            # captures mutations made through BytesIO.getbuffer().
            "dirty": True,
        }

        if "b" in mode:
            if any(kwargs.get(name) is not None for name in ("encoding", "errors", "newline")):
                raise ValueError("binary mode doesn't take an encoding, errors, or newline")
            buffer = _EncryptedBytesBuffer(plaintext, **writeback)
        else:
            encoding, errors, newline = self._text_options(args, kwargs)
            text = plaintext.decode(encoding, errors=errors)
            buffer = _EncryptedTextBuffer(
                text,
                encoding=encoding,
                errors=errors,
                newline=newline,
                **writeback,
            )

        if "a" in mode:
            buffer.seek(0, io.SEEK_END)
        else:
            buffer.seek(0)
        return buffer

    def _patched_open(self, file, mode="r", *args, **kwargs):
        """Decrypt reads and atomically re-encrypt writes to AILatch files."""
        if isinstance(file, (str, Path, pathlib.PurePath)):
            mode_str = mode if isinstance(mode, str) else "r"
            encrypted = self._is_encrypted_file(file)
            has_write = any(flag in mode_str for flag in ("w", "a", "x", "+"))

            if encrypted and has_write:
                return self._open_encrypted_for_write(file, mode_str, args, kwargs)

            if encrypted:
                # Skip .py files - those are handled by the import hook
                filepath_str = str(file)
                if filepath_str.endswith(".py"):
                    # Check if this call is from the import system
                    # by inspecting the call stack
                    import traceback as _tb
                    frame_info = _tb.extract_stack(limit=6)
                    from_import = any(
                        "importlib" in f.filename or "linecache" in f.filename
                        for f in frame_info
                    )
                    if from_import:
                        return self._original_open(file, mode, *args, **kwargs)

                plaintext = self._decrypt_file(file)
                if "b" in mode_str:
                    return io.BytesIO(plaintext)
                else:
                    encoding, errors, newline = self._text_options(args, kwargs)
                    return io.StringIO(
                        plaintext.decode(encoding, errors=errors),
                        newline=newline,
                    )

        return self._original_open(file, mode, *args, **kwargs)
