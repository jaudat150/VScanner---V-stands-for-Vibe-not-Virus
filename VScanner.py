# DeepSecurityScannerGUI_v2.py
# - Auto VirusTotal lookup for suspicious files (uses VT v3 file lookup by SHA256)
# - Copy selected / copy all / export CSV context menu + Ctrl+C
# - Thread-safe UI updates
# - Conservative rate-limit/backoff handling

import os
import threading
import time
import hashlib
import json
import csv
import subprocess
import platform
from tkinter import Tk, Frame, Label, Button, Entry, messagebox, StringVar, filedialog, ttk, Menu

import psutil
import requests
import json
import os

if platform.system() != "Windows":
    raise SystemExit("This tool is for Windows only.")


from pathlib import Path

# Use config next to the script, not the current working directory
SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.json"


def load_api_key():
    """Load VirusTotal API key from config.json stored next to the script."""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                key = data.get("virustotal_api_key", "")
                return key.strip() if isinstance(key, str) else ""
    except Exception:
        # silently ignore parse errors
        pass
    return ""




SUSPICIOUS_DIRS = ["temp", "\\appdata\\", "\\downloads\\", "\\public\\"]

VT_LOOKUP_URL = "https://www.virustotal.com/api/v3/files/{}"

# ---------------- helpers ----------------
def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def suspicious_path(path):
    if not path:
        return True
    low = path.lower()
    return any(x in low for x in SUSPICIOUS_DIRS)

# ---------------- virus total lookup ----------------
def vt_lookup_by_hash(api_key, sha256_hash, timeout=30):
    """
    Query VirusTotal v3 files/{hash}.
    Returns JSON on 200, None on 404, raises RuntimeError for other status codes.
    """
    headers = {"x-apikey": api_key}
    url = VT_LOOKUP_URL.format(sha256_hash)
    resp = requests.get(url, headers=headers, timeout=timeout)
    if resp.status_code == 200:
        return resp.json()
    if resp.status_code == 404:
        return None
    if resp.status_code == 429:
        # caller should handle backoff
        raise RuntimeError("RATE_LIMIT")
    raise RuntimeError(f"VT API error {resp.status_code}: {resp.text[:300]}")

# ---------------- windows scans ----------------
def scan_processes():
    results = []
    for p in psutil.process_iter(["pid", "name", "exe", "username"]):
        try:
            info = p.info
            pid = info.get("pid")
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            user = info.get("username") or ""

            flags = []
            if not exe:
                flags.append("NO_PATH")
            if suspicious_path(exe):
                flags.append("SUSPICIOUS_PATH")
            if exe and not os.path.exists(exe):
                flags.append("MISSING_FILE")
            try:
                conns = p.net_connections(kind="inet")
                if conns:
                    flags.append("NETWORK")
            except Exception:
                pass

            results.append({"pid": pid, "name": name, "exe": exe, "user": user, "flags": flags})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results

def scan_startup():
    keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    ]
    out = []
    for k in keys:
        try:
            proc = subprocess.run(["reg", "query", k], capture_output=True, text=True)
            if proc.returncode != 0:
                continue
            for ln in proc.stdout.splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("HKEY"):
                    continue
                parts = [p.strip() for p in ln.split("    ") if p.strip()]
                if len(parts) >= 2:
                    out.append({"key": k, "name": parts[0], "value": parts[-1]})
        except Exception:
            continue
    return out

def scan_schtasks():
    try:
        proc = subprocess.run(["schtasks", "/query", "/fo", "LIST"], capture_output=True, text=True)
        items = []
        current = {}
        for ln in proc.stdout.splitlines():
            if not ln.strip():
                if current:
                    items.append(current)
                current = {}
                continue
            if ":" in ln:
                k, v = ln.split(":", 1)
                current[k.strip()] = v.strip()
        if current:
            items.append(current)
        return items
    except Exception:
        return []

def scan_services_non_microsoft():
    out = []
    for s in psutil.win_service_iter():
        try:
            info = s.as_dict()
            path = info.get("binpath") or ""
            if path and ("windows" not in path.lower() or suspicious_path(path)):
                out.append({
                    "name": info.get("name"),
                    "display": info.get("display_name"),
                    "binpath": path,
                    "status": info.get("status"),
                })
        except Exception:
            pass
    return out

# ---------------- GUI ----------------
class App:
    def __init__(self, root):
        self.root = root
        root.title("VScanner ( V stands for Vibe not Virus )")
        root.geometry("1100x720")

        top = Frame(root)
        top.pack(fill="x", padx=6, pady=6)

        self.api_key_var = StringVar()
        self.api_key_var.set(load_api_key())


        Label(top, text="VirusTotal API key:").pack(side="left")
        Entry(top, textvariable=self.api_key_var, width=45, show="*").pack(side="left", padx=4)
        Button(top, text="Save Key", command=self.save_api_key).pack(side="left", padx=4)
        Button(top, text="Scan", command=self.start_scan).pack(side="left", padx=4)
        Button(top, text="VT Check All", command=self.vt_check_all_click).pack(side="left", padx=4)
        Button(top, text="Export current tab CSV", command=self.export_current_tab).pack(side="left", padx=4)

        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True)

        self.proc_tree = self.make_tab("Processes", ["PID", "Name", "Exe", "User", "Flags"])
        self.susp_tree = self.make_tab("Suspicious Files", ["Path", "SHA256", "VT"])

        # store results
        self.results = {}
        # used to cancel a running vt thread if needed
        self._vt_thread = None
        self._stop_vt = threading.Event()

    def make_tab(self, title, cols):
        frame = Frame(self.nb)
        self.nb.add(frame, text=title)

        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=300 if c == "Exe" or c == "Path" else 120)
        tree.pack(fill="both", expand=True)

        # context menu
        menu = Menu(tree, tearoff=0)
        menu.add_command(label="Copy selected", command=lambda t=tree: self.copy_selected(t))
        menu.add_command(label="Copy all", command=lambda t=tree: self.copy_all(t))
        menu.add_command(label="Export CSV", command=lambda t=tree: self.export_tree_csv(t))
        # open containing folder (for process trees)
        menu.add_separator()
        menu.add_command(label="Open location (selected)", command=self.open_location_selected)

        def on_right_click(event, m=menu):
            try:
                m.tk_popup(event.x_root, event.y_root)
            finally:
                m.grab_release()
        tree.bind("<Button-3>", on_right_click)

        # Ctrl+C
        tree.bind("<Control-c>", lambda e, t=tree: self.copy_selected(t))

        return tree

    # copy helpers
    def copy_selected(self, tree):
        rows = []
        for iid in tree.selection():
            vals = tree.item(iid, "values")
            # join with tab for easy paste into Excel
            rows.append("\t".join(str(v) for v in vals))
        if not rows:
            messagebox.showinfo("Copy", "No rows selected.")
            return
        text = "\n".join(rows)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", f"Copied {len(rows)} rows to clipboard.")

    def copy_all(self, tree):
        rows = []
        for iid in tree.get_children():
            vals = tree.item(iid, "values")
            rows.append("\t".join(str(v) for v in vals))
        if not rows:
            messagebox.showinfo("Copy", "No rows to copy.")
            return
        text = "\n".join(rows)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", f"Copied {len(rows)} rows to clipboard.")

    # export CSV
    def export_tree_csv(self, tree):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv"),("All","*.*")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            cols = tree["columns"]
            writer.writerow(cols)
            for iid in tree.get_children():
                writer.writerow(tree.item(iid)["values"])
        messagebox.showinfo("Exported", path)

    def export_current_tab(self):
        tab = self.nb.select()
        frame = self.root.nametowidget(tab)
        # first child should be tree
        children = frame.winfo_children()
        if not children:
            messagebox.showwarning("Export", "No table here.")
            return
        tree = children[0]
        self.export_tree_csv(tree)

    # scanning
    def start_scan(self):
        threading.Thread(target=self.scan_thread, daemon=True).start()

    def scan_thread(self):
        procs = scan_processes()
        startup = scan_startup()
        tasks = scan_schtasks()
        services = scan_services_non_microsoft()
        # build suspicious list
        suspicious = []
        seen = set()
        for p in procs:
            exe = p.get("exe") or ""
            if exe and suspicious_path(exe) and exe not in seen:
                seen.add(exe)
                suspicious.append({"path": exe, "sha256": sha256(exe)})

        self.results = {"processes": procs, "startup": startup, "tasks": tasks, "services": services, "suspicious": suspicious}
        # update GUI
        self.root.after(0, self.populate_ui)

    def populate_ui(self):
        # clear
        for t in [self.proc_tree, self.susp_tree]:
            for i in t.get_children():
                t.delete(i)

        # processes
        for p in self.results.get("processes", []):
            self.proc_tree.insert("", "end", values=(p["pid"], p["name"], p["exe"], p["user"], ",".join(p["flags"])))

        # suspicious
        for s in self.results.get("suspicious", []):
            self.susp_tree.insert("", "end", values=(s["path"], s["sha256"] or "", "not checked"))

        messagebox.showinfo("Scan", "Scan complete.")

    # open containing folder for selected process or selected suspicious file
    def open_location_selected(self):
        # prefer process selection
        sels = self.proc_tree.selection()
        path = None
        if sels:
            vals = self.proc_tree.item(sels[0], "values")
            path = vals[2] if len(vals) > 2 else None
        else:
            # fallback to suspicious selection
            sels = self.susp_tree.selection()
            if sels:
                vals = self.susp_tree.item(sels[0], "values")
                path = vals[0] if len(vals) > 0 else None

        if not path:
            messagebox.showwarning("Open location", "No file path available for selection.")
            return
        if not os.path.exists(path):
            messagebox.showwarning("Open location", "File does not exist.")
            return
        folder = os.path.dirname(path)
        subprocess.Popen(["explorer", folder])

    # ---------------- VirusTotal bulk check ----------------
    def vt_check_all_click(self):
        api_key = self.api_key_var.get().strip()
        if not api_key:
            api_key = load_api_key()  # auto-read from config.json
            self.api_key_var.set(api_key)
        if not api_key:
            messagebox.showwarning(
                "VirusTotal", 
                "No API key provided. Save it via the Save Key button."
            )
            return

    


        # stop any running vt thread
        self._stop_vt.set()
        if self._vt_thread and self._vt_thread.is_alive():
            # let it stop
            time.sleep(0.1)
        self._stop_vt.clear()
        self._vt_thread = threading.Thread(target=self._vt_check_all_thread, args=(api_key,), daemon=True)
        self._vt_thread.start()
        messagebox.showinfo("VirusTotal", "Started VirusTotal checks in background. Results will update in the table as they arrive.")

    def _vt_check_all_thread(self, api_key):
        # conservative delay between requests (seconds) to avoid hitting strict rate limits.
        delay = 10
        for iid in self.susp_tree.get_children():
            if self._stop_vt.is_set():
                break
            vals = self.susp_tree.item(iid, "values")
            path = vals[0]
            sha = vals[1]
            if not sha:
                # update row to "no hash"
                self._update_susp_row(iid, path, sha, "no-hash")
                continue
            # try lookup, with backoff on RATE_LIMIT
            backoff = 1
            while not self._stop_vt.is_set():
                try:
                    data = vt_lookup_by_hash(api_key, sha)
                    if data is None:
                        # not found on VT
                        self._update_susp_row(iid, path, sha, "not found")
                        break
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    self._update_susp_row(iid, path, sha, f"{positives}/{total}")
                    break
                except RuntimeError as e:
                    txt = str(e)
                    if "RATE_LIMIT" in txt or "429" in txt:
                        # backoff and retry
                        wait = delay * backoff
                        backoff = min(backoff * 2, 8)
                        self._update_susp_row(iid, path, sha, f"rate-limit, retrying in {wait}s")
                        time.sleep(wait)
                        continue
                    else:
                        self._update_susp_row(iid, path, sha, "error")
                        break
                except Exception:
                    self._update_susp_row(iid, path, sha, "error")
                    break
            # small pause between successful lookups too
            time.sleep(delay)
        # finished
        # optionally notify (do not interrupt the user)
        self.root.after(0, lambda: messagebox.showinfo("VirusTotal", "Background VT checks finished (or stopped)."))

    def _update_susp_row(self, iid, path, sha, vt_text):
        # update GUI safely from worker thread
        def upd():
            try:
                self.susp_tree.item(iid, values=(path, sha, vt_text))
            except Exception:
                pass
        self.root.after(0, upd)
    def save_api_key(self):
        key = self.api_key_var.get().strip()
        if not key:
            messagebox.showwarning("Save Key", "API key is empty!")
            return
        try:
            # Ensure the script folder exists (it will) and write config next to the script
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump({"virustotal_api_key": key}, f, indent=2)
            messagebox.showinfo("Save Key", f"API key saved to\n{CONFIG_PATH}")
        except Exception as e:
            messagebox.showerror("Save Key", str(e))


# ---------------- run ----------------
if __name__ == "__main__":
    root = Tk()
    App(root)
    root.mainloop()
