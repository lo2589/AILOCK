"""
AiLock GUI Editor — tkinter-based encrypted file viewer/editor.

Opens a dual-pane window: file tree on the left, text editor on the right.
Decryption runs in a background thread to keep the UI responsive.
"""

from __future__ import annotations

import os
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from pathlib import Path

from aloc.fileops import read_bytes, atomic_write
from aloc.format import is_locked


# Directories to skip
_SKIP_DIRS = {".ailock", "__pycache__", ".git", "node_modules", ".venv", "venv"}
_SKIP_SUFFIXES = {".pyc", ".pyo", ".so", ".dylib", ".dll"}


class AilockEditor:
    """A simple dual-pane GUI editor for ailock-encrypted files."""

    def __init__(self, root: tk.Tk, directory: Path, password: str):
        self.root = root
        self.directory = directory.resolve()
        self.password = password
        self.current_file: Path | None = None
        self.current_is_locked = False
        self._modified = False

        self.root.title(f"AiLock - {self.directory.name}/")
        self.root.geometry("900x600")
        self.root.minsize(600, 400)

        self._build_ui()
        self._build_file_tree()
        self._bind_events()

    def _build_ui(self):
        """Construct the UI layout."""
        # Main paned window
        self.paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True)

        # --- Left panel: file tree ---
        left_frame = ttk.Frame(self.paned, width=250)
        self.paned.add(left_frame, weight=1)

        self.tree = ttk.Treeview(left_frame, show="tree")
        tree_scroll = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # --- Right panel: text editor ---
        right_frame = ttk.Frame(self.paned)
        self.paned.add(right_frame, weight=3)

        # Toolbar
        toolbar = ttk.Frame(right_frame)
        toolbar.pack(fill=tk.X, padx=2, pady=2)

        self.save_btn = ttk.Button(toolbar, text="Save (Ctrl+S)", command=self._save_file)
        self.save_btn.pack(side=tk.LEFT, padx=2)

        self.file_label = ttk.Label(toolbar, text="No file selected")
        self.file_label.pack(side=tk.LEFT, padx=10)

        # Text area
        text_frame = ttk.Frame(right_frame)
        text_frame.pack(fill=tk.BOTH, expand=True)

        self.text = tk.Text(text_frame, wrap=tk.NONE, undo=True, font=("Courier", 12))
        text_yscroll = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.text.yview)
        text_xscroll = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL, command=self.text.xview)
        self.text.configure(yscrollcommand=text_yscroll.set, xscrollcommand=text_xscroll.set)

        self.text.grid(row=0, column=0, sticky="nsew")
        text_yscroll.grid(row=0, column=1, sticky="ns")
        text_xscroll.grid(row=1, column=0, sticky="ew")
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    def _build_file_tree(self):
        """Scan directory and populate the file tree."""
        self.tree.delete(*self.tree.get_children())
        self._file_map = {}  # tree item id -> file path

        self._insert_dir(self.directory, "")

    def _insert_dir(self, dir_path: Path, parent_id: str):
        """Recursively insert directory contents into tree."""
        try:
            entries = sorted(dir_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except PermissionError:
            return

        for entry in entries:
            rel = entry.relative_to(self.directory)

            # Skip hidden/ignored
            if entry.name.startswith(".") and entry.name != ".":
                continue
            if entry.is_dir():
                if entry.name in _SKIP_DIRS:
                    continue
                dir_id = self.tree.insert(parent_id, tk.END, text=f"[{entry.name}]", open=False)
                self._insert_dir(entry, dir_id)
            else:
                if entry.suffix in _SKIP_SUFFIXES:
                    continue
                # Check if locked
                try:
                    blob = read_bytes(entry)
                    locked = is_locked(blob)
                except Exception:
                    locked = False

                prefix = "* " if locked else "  "
                item_id = self.tree.insert(parent_id, tk.END, text=f"{prefix}{entry.name}")
                self._file_map[item_id] = entry

    def _bind_events(self):
        """Bind UI events."""
        self.tree.bind("<<TreeviewSelect>>", self._on_file_select)
        self.root.bind("<Control-s>", self._save_file)
        self.root.bind("<Command-s>", self._save_file)  # macOS
        self.text.bind("<<Modified>>", self._on_text_modified)

    def _on_text_modified(self, event=None):
        """Track modification state."""
        if self.text.edit_modified():
            self._modified = True
            if self.current_file:
                self.file_label.config(text=f"{self.current_file.name} [modified]")

    def _on_file_select(self, event):
        """Handle file tree selection."""
        selected = self.tree.selection()
        if not selected:
            return

        item_id = selected[0]
        file_path = self._file_map.get(item_id)
        if file_path is None:
            return  # It's a directory node

        # Check if current file has unsaved changes
        if self._modified and self.current_file:
            answer = messagebox.askyesnocancel(
                "Unsaved Changes",
                f"Save changes to {self.current_file.name}?"
            )
            if answer is None:  # Cancel
                return
            if answer:  # Yes
                self._do_save()

        self.current_file = file_path
        self._modified = False
        self.text.edit_modified(False)

        # Read and decrypt
        blob = read_bytes(file_path)
        if is_locked(blob):
            self.current_is_locked = True
            self._set_status("Decrypting...")
            self.text.config(state=tk.NORMAL)
            self.text.delete("1.0", tk.END)
            self.text.insert("1.0", "Decrypting...")
            self.text.config(state=tk.DISABLED)
            self.file_label.config(text=f"{file_path.name} [locked]")

            # Decrypt in background thread
            thread = threading.Thread(target=self._decrypt_async, args=(blob,), daemon=True)
            thread.start()
        else:
            self.current_is_locked = False
            # Plain file, display directly
            try:
                content = blob.decode("utf-8")
            except UnicodeDecodeError:
                content = blob.decode("latin-1")
            self._display_content(content)
            self.file_label.config(text=f"{file_path.name} [plain]")
            self._set_status("Ready")

    def _decrypt_async(self, blob: bytes):
        """Decrypt file in background thread."""
        from aloc.cli import _decrypt_with_password

        t0 = time.time()
        try:
            plaintext = _decrypt_with_password(blob, self.password)
            content = plaintext.decode("utf-8")
            elapsed = time.time() - t0
            self.root.after(0, self._display_content, content)
            self.root.after(0, self._set_status, f"Decrypted in {elapsed:.2f}s")
        except Exception as e:
            self.root.after(0, self._display_error, str(e))

    def _display_content(self, content: str):
        """Update text widget with decrypted content (must run on main thread)."""
        self.text.config(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", content)
        self.text.edit_modified(False)
        self._modified = False
        if self.current_file:
            status = "locked" if self.current_is_locked else "plain"
            self.file_label.config(text=f"{self.current_file.name} [{status}]")

    def _display_error(self, error_msg: str):
        """Display error in text area."""
        self.text.config(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", f"Error: {error_msg}")
        self.text.config(state=tk.DISABLED)
        self._set_status(f"Error: {error_msg}")

    def _save_file(self, event=None):
        """Save current file (encrypt if it was locked)."""
        if self.current_file is None:
            return
        if not self._modified:
            self._set_status("No changes to save")
            return

        self._do_save()

    def _do_save(self):
        """Perform the actual save operation."""
        if self.current_file is None:
            return

        content = self.text.get("1.0", tk.END)
        # tk.Text always appends a trailing newline, remove it
        if content.endswith("\n"):
            content = content[:-1]

        self._set_status("Saving...")
        self.save_btn.config(state=tk.DISABLED)

        thread = threading.Thread(
            target=self._save_async,
            args=(self.current_file, content.encode("utf-8"), self.current_is_locked),
            daemon=True,
        )
        thread.start()

    def _save_async(self, path: Path, data: bytes, encrypt: bool):
        """Save (and optionally re-encrypt) in background thread."""
        import base64
        from aloc.crypto import (
            derive_project_key, generate_file_key,
            encrypt_payload_v2, wrap_key,
        )
        from aloc.format import encode_file

        try:
            if encrypt:
                # Re-encrypt with the same password
                salt = os.urandom(16)
                file_key = generate_file_key()
                metadata = {
                    "filename": path.name,
                    "mode": path.stat().st_mode if path.exists() else 0o644,
                    "mtime": int(time.time()),
                }
                nonce, ciphertext = encrypt_payload_v2(file_key, data, metadata)

                pw_key = derive_project_key(self.password, salt)
                pw_nonce, pw_wrapped = wrap_key(pw_key, file_key)

                header = {
                    "kdf": "argon2id",
                    "aead": "chacha20poly1305",
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "key_wraps": [
                        {
                            "type": "password",
                            "nonce": base64.b64encode(pw_nonce).decode("ascii"),
                            "wrapped": base64.b64encode(pw_wrapped).decode("ascii"),
                        }
                    ],
                    "meta": metadata,
                }

                blob = encode_file(header, ciphertext)
                atomic_write(path, blob)
            else:
                # Plain file, just write
                atomic_write(path, data)

            self.root.after(0, self._on_save_done, path)
        except Exception as e:
            self.root.after(0, self._on_save_error, str(e))

    def _on_save_done(self, path: Path):
        """Save completed callback (main thread)."""
        self._modified = False
        self.text.edit_modified(False)
        self.save_btn.config(state=tk.NORMAL)
        status = "locked" if self.current_is_locked else "plain"
        self.file_label.config(text=f"{path.name} [{status}]")
        self._set_status(f"Saved: {path.name}")

    def _on_save_error(self, error_msg: str):
        """Save error callback (main thread)."""
        self.save_btn.config(state=tk.NORMAL)
        self._set_status(f"Save error: {error_msg}")
        messagebox.showerror("Save Error", error_msg)

    def _set_status(self, msg: str):
        """Update status bar."""
        self.status_var.set(msg)


def launch_editor(directory: Path, password: str):
    """Launch the AiLock GUI editor."""
    root = tk.Tk()
    AilockEditor(root, directory, password)
    root.mainloop()
