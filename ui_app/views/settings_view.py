# ui-app/views/settings_view.py

import os
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox
import threading

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

from client import exceptions

class SettingsView(tk.Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        main_frame = ttk.Frame(self, padding=20)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)

        wallet_frame = ttk.LabelFrame(main_frame, text="My Account Info", padding=15)
        wallet_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        wallet_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(wallet_frame, text="Wallet Address:", font="-weight bold").grid(row=0, column=0, sticky="w", pady=2)
        
        self.address_var = tk.StringVar(value="...")
        address_entry = ttk.Entry(wallet_frame, textvariable=self.address_var, state="readonly")
        address_entry.grid(row=0, column=1, sticky="ew", padx=5)

        copy_address_btn = ttk.Button(wallet_frame, text="Copy", command=self.copy_address)
        copy_address_btn.grid(row=0, column=2, padx=(5, 0))

        ttk.Label(wallet_frame, text="Sharing Public Key:", font="-weight bold").grid(row=1, column=0, sticky="w", pady=2)
        
        self.pubkey_var = tk.StringVar(value="...")
        pubkey_entry = ttk.Entry(wallet_frame, textvariable=self.pubkey_var, state="readonly")
        pubkey_entry.grid(row=1, column=1, sticky="ew", padx=5)
        
        copy_pubkey_btn = ttk.Button(wallet_frame, text="Copy", command=self.copy_pubkey)
        copy_pubkey_btn.grid(row=1, column=2, padx=(5, 0))

        security_frame = ttk.LabelFrame(main_frame, text="Security Actions", padding=15)
        security_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))

        resave_shares_btn = ttk.Button(security_frame, text="Generate New Master Key Shares", command=self.handle_resave_shares)
        resave_shares_btn.pack(side="left", padx=5)

        danger_frame = ttk.LabelFrame(main_frame, text="Danger Zone", padding=15, bootstyle="danger")
        danger_frame.grid(row=2, column=0, sticky="ew")

        reset_button = ttk.Button(danger_frame, text="Reset All My Indexes", 
                                  bootstyle="danger", 
                                  command=self.handle_reset_indexes)
        reset_button.pack(side="left", padx=5)
        
        ttk.Label(danger_frame, text="This will clear all file lists but not the files themselves.").pack(side="left", padx=10)

        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        status_bar.grid(row=1, column=0, sticky="ew")

    def on_show(self):
        self.status_var.set("Settings loaded.")
        if self.controller.client:
            self.address_var.set(self.controller.client.get_logged_in_address())
            try:
                pubkey = self.controller.client.get_my_umbral_public_key()
                self.pubkey_var.set(f"{pubkey[:12]}...{pubkey[-12:]}")
            except exceptions.ClientError as e:
                self.pubkey_var.set(f"Error: {e}")
        else:
            self.address_var.set("Not logged in.")
            self.pubkey_var.set("Not logged in.")
    def copy_pubkey(self):
        if not self.controller.client or not self.controller.client.session_umbral_private_key:
            messagebox.showerror("Error", "You must be logged in to copy your public key.")
            return
        
        try:
            full_pubkey = self.controller.client.get_my_umbral_public_key()
            self.clipboard_clear()
            self.clipboard_append(full_pubkey)
            self.status_var.set("Sharing Public Key copied to clipboard!")
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            messagebox.showerror("Error", f"Could not copy public key: {e}")

    def copy_address(self):
        if not self.controller.client:
            messagebox.showerror("Error", "You must be logged in.")
            return
        
        try:
            full_address = self.controller.client.get_logged_in_address()
            self.clipboard_clear()
            self.clipboard_append(full_address)
            self.status_var.set("Wallet Address copied to clipboard!")
        except Exception as e:
            self.status_var.set(f"Error: {e}")
    def handle_reset_indexes(self):
        if not messagebox.askyesno("Confirm Reset", 
            "WARNING: This will clear all your file lists.\n\n"
            "Your underlying files will NOT be deleted, but they will no longer appear in your indexes. "
            "This action cannot be undone.\n\nAre you absolutely sure you want to proceed?"):
            return
            
        if not messagebox.askyesno("Final Confirmation", 
            "Final warning: All on-chain index pointers will be overwritten. Proceed?"):
            return

        thread = threading.Thread(target=self._reset_worker)
        thread.daemon = True
        thread.start()

    def _reset_worker(self):
        try:
            self.after(0, self.status_var.set, "Resetting indexes... This may take several moments.")
            self.after(0, lambda: self.winfo_children()[0].config(cursor="watch")) # Set busy cursor
            
            self.controller.client.reset_all_indexes()
            
            self.after(0, self.on_reset_success)
        except Exception as e:
            self.after(0, self.on_reset_error, e)
        finally:
            self.after(0, lambda: self.winfo_children()[0].config(cursor="")) # Reset cursor

    def on_reset_success(self):
        self.status_var.set("All indexes have been successfully reset.")
        messagebox.showinfo("Success", "Your indexes have been reset to an empty state. You may need to refresh your dashboard.")
        
    def on_reset_error(self, error):
        self.status_var.set(f"Failed to reset indexes: {error}")
        messagebox.showerror("Error", f"An error occurred during the reset: {error}")
    def handle_resave_shares(self):
        if not self.controller.client or not self.controller.client.session_master_key:
            messagebox.showerror("Error", "You must be logged in with an active master key to perform this action.")
            return

        if not messagebox.askyesno("Confirm New Shares",
            "This will generate a completely NEW set of 5 master key shares.\n\n"
            "You MUST save these new shares securely. Your old shares may no longer be sufficient to recover your key.\n\n"
            "Are you sure you want to proceed?"):
            return

        try:
            new_shares = self.controller.client.generate_new_shares_from_session_key()
            self.show_new_shares_popup(new_shares)

        except exceptions.ClientError as e:
            messagebox.showerror("Error", f"Could not generate new shares: {e}")

    def show_new_shares_popup(self, new_shares: list[str]):
        popup = ttk.Toplevel(self)
        popup.title("Your New Master Key Shares")
        popup.transient(self)
        popup.grab_set() 
        popup.geometry("550x400")
        
        content_frame = ttk.Frame(popup, padding=20)
        content_frame.pack(fill="both", expand=True)

        warning_text = (
            "IMPORTANT: Save these new shares immediately!\n"
            "These are the ONLY copies. This window will not be shown again."
        )
        warning_label = ttk.Label(content_frame, text=warning_text, bootstyle="warning", justify="center")
        warning_label.pack(pady=(0, 15))

        shares_text_widget = tk.Text(content_frame, height=8, width=60, wrap="word", font="TkFixedFont")
        shares_text_widget.pack(pady=(0, 15), fill="x", expand=True)
        
        display_text = "\n".join(new_shares)
        shares_text_widget.insert(tk.END, display_text)
        shares_text_widget.config(state="disabled")

        button_frame = ttk.Frame(content_frame)
        button_frame.pack()

        def save_popup_shares():
            dir_path = filedialog.askdirectory(title="Select a Secure Folder to Save Your New Share Files")
            if dir_path:
                try:
                    short_address = self.controller.client.get_logged_in_address()[-6:]
                    for i, share in enumerate(new_shares, 1):
                        filename = f"new_master_key_share_{i}_of_5_{short_address}.txt"
                        filepath = os.path.join(dir_path, filename)
                        with open(filepath, 'w') as f:
                            f.write(f"NEW MASTER KEY SHARE {i}/5\n" + "="*60 + "\n\n" + share)
                    messagebox.showinfo("Success", f"Successfully saved 5 new share files to:\n{dir_path}", parent=popup)
                except Exception as e:
                    messagebox.showerror("Save Failed", f"An error occurred: {e}", parent=popup)

        save_button = ttk.Button(button_frame, text="Save New Shares to Files...", command=save_popup_shares)
        save_button.pack(side="left", padx=10)
        
        close_button = ttk.Button(button_frame, text="Close", command=popup.destroy, style="success.TButton")
        close_button.pack(side="left", padx=10)