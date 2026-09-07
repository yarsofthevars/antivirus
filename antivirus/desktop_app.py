"""Desktop Window Application for Box of Kingles: The AntiVirus!"""

import os
import subprocess
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
from typing import Optional

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from .scanner import scan_file, scan_directory
from .monitor import FileMonitor
from .quarantine import list_quarantine
from .config import load_config, get_config_dir
from .exclusions import load_exclusions

# Assets - use absolute path to ensure it works
ASSETS_DIR = Path(__file__).resolve().parent / "assets"
SOVIET_MARCH = str(ASSETS_DIR / "soviet_march.mp3")
WIDE_PUTIN_IMG = str(ASSETS_DIR / "wide_putin_big.png")


class AntivirusDesktopApp:
    """Box of Kingles Desktop Application."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Box of Kingles: The AntiVirus!")
        self.root.geometry("350x450")
        self.root.configure(bg="#1a1a2e")
        self.root.resizable(False, False)

        # Make window stay on top
        self.root.attributes("-topmost", True)

        self.monitor: Optional[FileMonitor] = None
        self.music_process: Optional[subprocess.Popen] = None
        self.music_enabled = True
        self.config = load_config()
        self.protection_on = False

        self.setup_ui()
        self.play_soviet_march()

    def setup_ui(self):
        """Setup the user interface."""
        bg_color = "#1a1a2e"
        fg_color = "#eee"
        btn_color = "#e94560"

        # Wide Putin image
        putin_loaded = False
        if HAS_PIL and Path(WIDE_PUTIN_IMG).exists():
            try:
                img = Image.open(WIDE_PUTIN_IMG)
                # Scale up to 150x150 for visibility
                img = img.resize((150, 150), Image.Resampling.NEAREST)
                self.putin_img = ImageTk.PhotoImage(img)
                putin_label = tk.Label(self.root, image=self.putin_img, bg=bg_color)
                putin_label.pack(pady=(20, 5))
                putin_loaded = True
            except Exception as e:
                print(f"Image error: {e}")

        if not putin_loaded:
            # Fallback to emoji
            title = tk.Label(
                self.root,
                text="🛡️",
                font=("Arial", 64),
                bg=bg_color,
                fg=fg_color
            )
            title.pack(pady=(20, 5))

        name_label = tk.Label(
            self.root,
            text="Box of Kingles",
            font=("Helvetica", 22, "bold"),
            bg=bg_color,
            fg=fg_color
        )
        name_label.pack()

        subtitle = tk.Label(
            self.root,
            text="The AntiVirus!",
            font=("Helvetica", 12),
            bg=bg_color,
            fg="#888"
        )
        subtitle.pack(pady=(0, 15))

        # Protection status
        self.status_label = tk.Label(
            self.root,
            text="⏸️ Protection: OFF",
            font=("Helvetica", 14),
            bg=bg_color,
            fg="#ff6b6b"
        )
        self.status_label.pack(pady=5)

        # Protection button
        self.protection_btn = tk.Button(
            self.root,
            text="Enable Protection",
            font=("Helvetica", 12),
            bg=btn_color,
            fg="white",
            activebackground="#ff6b6b",
            activeforeground="white",
            relief=tk.FLAT,
            padx=20,
            pady=8,
            command=self.toggle_protection
        )
        self.protection_btn.pack(pady=10)

        # Divider
        tk.Frame(self.root, height=2, bg="#333").pack(fill=tk.X, padx=20, pady=10)

        # Scan buttons
        scan_label = tk.Label(
            self.root,
            text="Quick Scan",
            font=("Helvetica", 12, "bold"),
            bg=bg_color,
            fg=fg_color
        )
        scan_label.pack()

        btn_frame = tk.Frame(self.root, bg=bg_color)
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame, text="📁 Scan File", command=self.scan_file,
            bg="#16213e", fg=fg_color, relief=tk.FLAT, padx=10, pady=5
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame, text="📂 Scan Folder", command=self.scan_folder,
            bg="#16213e", fg=fg_color, relief=tk.FLAT, padx=10, pady=5
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            self.root, text="⬇️ Scan Downloads", command=self.scan_downloads,
            bg="#16213e", fg=fg_color, relief=tk.FLAT, padx=15, pady=5
        ).pack(pady=5)

        # Divider
        tk.Frame(self.root, height=2, bg="#333").pack(fill=tk.X, padx=20, pady=10)

        # Quarantine info
        entries = list_quarantine()
        quarantine_text = f"🗑️ Quarantine: {len(entries)} items"
        tk.Label(
            self.root, text=quarantine_text,
            font=("Helvetica", 11), bg=bg_color, fg=fg_color
        ).pack()

        # Music toggle
        self.music_btn = tk.Button(
            self.root,
            text="🔊 Silence the March",
            font=("Helvetica", 11),
            bg="#0f3460",
            fg=fg_color,
            relief=tk.FLAT,
            padx=15,
            pady=5,
            command=self.toggle_music
        )
        self.music_btn.pack(pady=15)

        # Quit
        tk.Button(
            self.root, text="Quit", command=self.quit_app,
            bg="#333", fg="#888", relief=tk.FLAT, padx=20, pady=5
        ).pack(pady=5)

    def toggle_protection(self):
        """Toggle real-time protection."""
        if self.protection_on:
            if self.monitor:
                self.monitor.stop()
                self.monitor = None
            self.protection_on = False
            self.status_label.config(text="⏸️ Protection: OFF", fg="#ff6b6b")
            self.protection_btn.config(text="Enable Protection")
        else:
            paths = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
            ]
            paths = [p for p in paths if os.path.exists(p)]

            self.monitor = FileMonitor(
                paths=paths,
                recursive=True,
                auto_quarantine=False,
                use_heuristics=self.config.heuristics.enabled,
                exclusion_config=load_exclusions(),
                on_threat=self.on_threat_detected,
            )
            self.monitor.start()
            self.protection_on = True
            self.status_label.config(text="🛡️ Protection: ON", fg="#4ecca3")
            self.protection_btn.config(text="Disable Protection")

    def on_threat_detected(self, path, threat_name, result):
        """Handle threat detection."""
        self.root.after(0, lambda: messagebox.showwarning(
            "Threat Detected!",
            f"Threat: {threat_name}\nFile: {path}"
        ))

    def scan_file(self):
        """Scan a single file."""
        filepath = filedialog.askopenfilename(title="Select file to scan")
        if filepath:
            self.run_scan(Path(filepath), is_directory=False)

    def scan_folder(self):
        """Scan a folder."""
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self.run_scan(Path(folder), is_directory=True)

    def scan_downloads(self):
        """Scan Downloads folder."""
        downloads = Path.home() / "Downloads"
        if downloads.exists():
            self.run_scan(downloads, is_directory=True)

    def run_scan(self, path: Path, is_directory: bool):
        """Run a scan in background."""
        def do_scan():
            try:
                if is_directory:
                    results = scan_directory(path, recursive=True, use_heuristics=True)
                else:
                    results = [scan_file(path, use_heuristics=True)]

                threats = [r for r in results if r.is_threat]

                self.root.after(0, lambda: messagebox.showinfo(
                    "Scan Complete",
                    f"Scanned {len(results)} files\nThreats found: {len(threats)}"
                ))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

        threading.Thread(target=do_scan, daemon=True).start()

    def play_soviet_march(self):
        """Play the Soviet March."""
        import sys
        print(f"play_soviet_march called, enabled={self.music_enabled}", flush=True)
        if not self.music_enabled:
            return
        march_path = Path(SOVIET_MARCH)
        print(f"March path: {march_path}, exists: {march_path.exists()}", flush=True)
        if march_path.exists():
            self.stop_music()
            try:
                self.music_process = subprocess.Popen(
                    ["afplay", str(march_path)],
                )
                print(f"Music started, PID: {self.music_process.pid}", flush=True)
            except Exception as e:
                print(f"Music error: {e}", flush=True)

    def stop_music(self):
        """Stop music."""
        if self.music_process:
            try:
                self.music_process.terminate()
                self.music_process = None
            except Exception:
                pass

    def toggle_music(self):
        """Toggle music on/off."""
        self.music_enabled = not self.music_enabled
        if self.music_enabled:
            self.play_soviet_march()
            self.music_btn.config(text="🔊 Silence the March")
        else:
            self.stop_music()
            self.music_btn.config(text="🔇 Play Soviet March")

    def quit_app(self):
        """Quit the application."""
        self.stop_music()
        if self.monitor:
            self.monitor.stop()
        self.root.destroy()

    def run(self):
        """Run the application."""
        self.root.mainloop()


def main():
    """Launch the desktop application."""
    app = AntivirusDesktopApp()
    app.run()


if __name__ == "__main__":
    main()
