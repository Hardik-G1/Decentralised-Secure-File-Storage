# ui-app/views/reconstruct_key_view.py

import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog
import threading 

from client import constants

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

class ReconstructKeyView(tk.Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        main_frame = ttk.Frame(self)
        main_frame.grid(row=0, column=0, sticky="")
        
        title_label = ttk.Label(main_frame, text="Login", font="-size 16 -weight bold")
        title_label.pack(pady=20)
        
        content_frame = ttk.Frame(main_frame, padding="20")
        content_frame.pack()
        
        info_text = f"Please provide at least {constants.MASTER_KEY_SSS_THRESHOLD} of your 5 master key shares to log in."
        info_label = ttk.Label(content_frame, text=info_text)
        info_label.pack(pady=(0, 15))
        
        self.share_vars = [tk.StringVar() for _ in range(5)]
        for i in range(5):
            share_frame = ttk.Frame(content_frame)
            share_frame.pack(pady=2, fill="x")
            ttk.Label(share_frame, text=f"Share {i+1}:", width=8).pack(side="left", padx=(0, 5))
            entry = ttk.Entry(share_frame, textvariable=self.share_vars[i], width=70)
            entry.pack(side="left", fill="x", expand=True)

        ttk.Separator(content_frame, orient="horizontal").pack(pady=15, fill="x")
        
        self.load_button = ttk.Button(
            content_frame,
            text="Load Shares From Files...",
            command=self.load_from_files,
            bootstyle="dark"
        )
        self.load_button.pack(pady=5, ipady=8)
        
        self.login_button = ttk.Button(
            content_frame,
            text="Reconstruct Key & Login",
            command=self.handle_login,
            width=30,
            bootstyle="primary-outline-toolbutton"
        )
        self.login_button.pack(pady=20, ipady=8)
        
        self.status_var = tk.StringVar()
        status_label = ttk.Label(content_frame, textvariable=self.status_var, bootstyle="danger")
        status_label.pack(pady=10)
    
    def on_show(self):
        for var in self.share_vars:
            var.set("")
        self.status_var.set("")

    def load_from_files(self):
        filepaths = filedialog.askopenfilenames(title="Select 3 or more of your saved share files", filetypes=[("Text Documents", "*.txt"), ("All Files", "*.*")])
        if not filepaths: return
        try:
            loaded_shares = []
            for filepath in filepaths:
                with open(filepath, 'r') as f: lines = [line.strip() for line in f.readlines()]
                share_value = ""
                for line in reversed(lines):
                    if line: share_value = line; break
                if share_value and len(share_value)==66:
                    loaded_shares.append(share_value)
            if not loaded_shares:
                self.status_var.set("Could not find any valid shares in the selected files.")
                return
            self.on_show()
            for i, share in enumerate(loaded_shares):
                if i < 5: self.share_vars[i].set(share)
            self.status_var.set(f"Success! Loaded {len(loaded_shares)} share(s) from your files.")
        except Exception as e:
            self.status_var.set(f"Failed to read files - {str(e)}")
            
    def handle_login(self):
        provided_shares = [var.get().strip() for var in self.share_vars if var.get().strip()]
        if len(provided_shares) < constants.MASTER_KEY_SSS_THRESHOLD:
            self.status_var.set(f"Error: Please provide at least {constants.MASTER_KEY_SSS_THRESHOLD} valid shares.")
            return

        self.status_var.set("Reconstructing keys and logging in... Please wait.")
        self.login_button.config(state="disabled")
        self.load_button.config(state="disabled")

        thread = threading.Thread(target=self._login_worker, args=(provided_shares,))
        thread.daemon = True
        thread.start()

    def _login_worker(self, shares):
        try:
            if not self.controller.client:
                raise Exception("Client not initialized.")
            
            self.controller.client.login_user(shares=shares)
            self.after(0, self.on_login_success)
        except Exception as e:
            self.after(0, self.on_login_error, e)

    def on_login_success(self):
        self.status_var.set("Success! Keys reconstructed. Logging in...")
        self.login_button.config(state="normal")
        self.load_button.config(state="normal")
        self.controller.show_frame("DashboardView")

    def on_login_error(self, error):
        self.status_var.set(f"{str(error)}")
        self.login_button.config(state="normal")
        self.load_button.config(state="normal")