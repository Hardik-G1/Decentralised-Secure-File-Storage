# ui-app/views/create_shares_view.py

import os
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox
import threading

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

class CreateSharesView(tk.Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller
        self.generated_shares = []
        self.umbral_key_hex = ""

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        main_container = ttk.Frame(self)
        main_container.grid(row=0, column=0, sticky="nsew")
        main_container.grid_columnconfigure(0, weight=1)
        
        center_frame = ttk.Frame(main_container)
        center_frame.grid(row=0, column=0, sticky="n", padx=20, pady=20)
        
        title_label = ttk.Label(
            center_frame,
            text="Step 1: Secure Your Account Keys",
            font="-size 16 -weight bold"
        )
        title_label.pack(pady=20)
        
        content_frame = ttk.Frame(center_frame)
        content_frame.pack(fill="both", expand=True)

        warning_frame = ttk.Frame(content_frame)
        warning_frame.pack(fill="x", pady=(0, 15), padx=20)
        
        warning_content = ttk.Frame(warning_frame)
        warning_content.pack(expand=True)
        
        warning_label = ttk.Label(
            warning_content,
            text="WARNING: CRITICAL SECURITY INFORMATION",
            font="-size 12 -weight bold",
            foreground="#cc0000",
            background="#ffebee",
            padding=10
        )
        warning_label.pack(pady=(0, 10))

        info_text = (
            "These are your Master Key Shares - They are the ONLY way to access your files!\n\n"
            "• You will receive 5 key share files\n"
            "• You need ANY 3 of these files to access your account\n"
            "  - Cloud Storage (Google Drive, Dropbox, MEGA)\n"
            "  - USB Drive or any Password Manager\n\n"
            "NEVER store all shares in the same place - This is crucial for security!"
        )
        
        info_label_shares = ttk.Label(
            warning_content,
            text=info_text,
            justify="center",
            font="-size 10",
            wraplength=800  # Ensure text wraps nicely
        )
        info_label_shares.pack(pady=10)

        shares_container = ttk.Frame(content_frame)
        shares_container.pack(fill="x", padx=20, pady=(10, 20))

        shares_label = ttk.Label(
            shares_container,
            text="Your Generated Key Shares:",
            font="-size 10 -weight bold"
        )
        shares_label.pack(anchor="w", pady=(0, 5))

        self.shares_text = tk.Text(
            shares_container,
            height=7,
            width=70,
            wrap="word",
            font="TkFixedFont",
            bg='#f8f9fa',
            relief="solid",
            borderwidth=1
        )
        self.shares_text.pack(fill="x")
        self.shares_text.configure(state="disabled")
        self.shares_text.tag_configure("center", justify="center")

        button_frame = ttk.Frame(content_frame)
        button_frame.pack(fill="x", padx=20, pady=10)

        save_button = ttk.Button(
            button_frame,
            text="💾 Save All Keys to Files...",
            command=self.save_keys,
            bootstyle="success",
            width=30
        )
        save_button.pack(pady=5, ipady=8)
        
        self.confirm_var = tk.BooleanVar()
        confirm_frame = ttk.Frame(content_frame)
        confirm_frame.pack(pady=15)
        
        confirm_check = ttk.Checkbutton(
            confirm_frame,
            text="I confirm that I have securely saved ALL my keys and shares in multiple locations",
            variable=self.confirm_var,
            command=self.toggle_proceed_button
        )
        confirm_check.pack()

        self.proceed_button = ttk.Button(
            content_frame,
            text="🚀 Step 2: Initialize On-Chain Account",
            command=self.handle_proceed,
            state="disabled",
            bootstyle="primary-outline-toolbutton",
            width=35
        )
        self.proceed_button.pack(pady=20, ipady=8)
        
        self.status_var = tk.StringVar()
        status_label = ttk.Label(
            content_frame,
            textvariable=self.status_var,
            bootstyle="info",
            font="-size 10",
            justify="center"
        )
        status_label.pack(pady=10)

    def on_show(self):
        self.status_var.set("Generating cryptographic keys... Please wait.")
        self.confirm_var.set(False)
        self.proceed_button.configure(state="disabled")
        for widget in [self.shares_text]:
             widget.configure(state="normal")
             widget.delete("1.0", tk.END)
             widget.insert(tk.END, "Generating...")
             widget.configure(state="disabled")
        
        thread = threading.Thread(target=self._generate_keys_worker)
        thread.daemon = True
        thread.start()
        
    def _generate_keys_worker(self):
        try:
            if not self.controller.client:
                raise Exception("Client not initialized.")
            
            setup_data = self.controller.client.setup_new_user()
            self.generated_shares = setup_data # It's now a list
            self.after(0, self.on_generation_success)
        except Exception as e:
            self.after(0, self.on_generation_error, e)
            
    def on_generation_success(self):
        display_text_shares = "\n".join(self.generated_shares)
        self.shares_text.configure(state="normal")
        self.shares_text.delete("1.0", tk.END)
        self.shares_text.insert("1.0", display_text_shares, "center")
        self.shares_text.configure(state="disabled")
        self.status_var.set("✅ Keys generated successfully. Please save them now to multiple secure locations.")

    def on_generation_error(self, error):
        self.status_var.set(f"Error during key generation: {error}")
        messagebox.showerror("Key Generation Failed", f"Could not generate keys: {error}")

    def handle_proceed(self):
        self.status_var.set("Initializing your on-chain account... This may take several moments.")
        self.proceed_button.configure(state="disabled")

        thread = threading.Thread(target=self._proceed_worker)
        thread.daemon = True
        thread.start()

    def _proceed_worker(self):
        try:
            self.controller.client.initialize_all_indexes()
            self.after(0, self.on_proceed_success)
        except Exception as e:
            self.after(0, self.on_proceed_error, e)

    def on_proceed_success(self):
        self.status_var.set("Account initialized successfully!")
        messagebox.showinfo("Setup Complete", "Your account has been successfully initialized on the blockchain.")
        self.controller.show_frame("DashboardView")

    def on_proceed_error(self, error):
        self.status_var.set(f"Error during initialization: {error}")
        self.proceed_button.configure(state="normal") # Re-enable button on failure
        messagebox.showerror("Initialization Failed", f"Could not initialize your account on-chain: {error}")

    def save_keys(self):
        if not self.generated_shares:
            messagebox.showerror("Error", "No shares have been generated yet.")
            return
        dir_path = filedialog.askdirectory(title="Select a Secure Folder to Save Your Key Files")
        if not dir_path: return
        try:
            short_address = self.controller.client.get_logged_in_address()[-6:]
            for i, share in enumerate(self.generated_shares, 1):
                share_filepath = os.path.join(dir_path, f"master_key_share_{i}_of_5_{short_address}.txt")
                with open(share_filepath, 'w') as f:
                    f.write(f"DECENTRALIZED SECURE FILE STORAGE - MASTER KEY SHARE {i}/5\n" + "="*60 + "\n\n" + share)
            messagebox.showinfo("Success", f"Successfully saved 5 share files to:\n{dir_path}")
        except Exception as e:
            messagebox.showerror("Save Failed", f"An error occurred while saving the files: {e}")

    def toggle_proceed_button(self):
        self.proceed_button.configure(state="normal" if self.confirm_var.get() else "disabled")