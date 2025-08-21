# ui-app/views/browse_others_view.py

import tkinter as tk
import ttkbootstrap as ttk
from tkinter import messagebox
import threading

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

from client import constants, crypto, exceptions
from client.offchain.index_manager import IndexManager

class BrowseOthersView(tk.Frame):
    """
    A view to browse the public-facing indexes (Public, Shared, Paid)
    of another user by entering their wallet address.
    """
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller

        self.browsed_address = ""
        self.current_file_list = []
        self.current_index_name = ""

        self.grid_rowconfigure(2, weight=1) 
        self.grid_columnconfigure(0, weight=1)

        action_bar = ttk.Frame(self, padding=(10, 10, 10, 5))
        action_bar.grid(row=0, column=0, sticky="ew")

        lookup_frame = ttk.Frame(self, padding=(20, 10))
        lookup_frame.grid(row=1, column=0, sticky="ew")
        lookup_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(lookup_frame, text="User's Wallet Address:").grid(row=0, column=0, padx=(0, 10))
        self.address_var = tk.StringVar()
        self.address_entry = ttk.Entry(lookup_frame, textvariable=self.address_var, width=50)
        self.address_entry.grid(row=0, column=1, sticky="ew")
        self.browse_button = ttk.Button(lookup_frame, text="Browse User", command=self.handle_browse_user)
        self.browse_button.grid(row=0, column=2, padx=(10, 0))

        self.content_frame = ttk.Frame(self, padding=10)
        self.content_frame.grid(row=2, column=0, sticky="nsew")
        self.content_frame.grid_rowconfigure(1, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)
        
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        status_bar.grid(row=3, column=0, sticky="ew")

    def on_show(self):
        self.address_var.set("")
        self.status_var.set("Enter another user's wallet address to browse their public files.")
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _set_ui_busy(self, is_busy, message=""):
        state = "disabled" if is_busy else "normal"
        self.address_entry.config(state=state)
        self.browse_button.config(state=state)
        if is_busy:
            self.status_var.set(message)
            self.update_idletasks()

    def handle_browse_user(self):
        address = self.address_var.get().strip()
        if not self.controller.client.w3.is_address(address):
            messagebox.showerror("Invalid Address", "Please enter a valid Ethereum wallet address.")
            return

        self.browsed_address = address
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        self._set_ui_busy(True, f"Looking up indexes for {address[:8]}...")
        
        self.populate_browse_view()
        self._set_ui_busy(False)
        self.status_var.set(f"Showing public indexes for {self.browsed_address[:8]}...")

    def populate_browse_view(self):
        index_frame = ttk.Frame(self.content_frame)
        index_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        index_frame.grid_columnconfigure((0, 1, 2), weight=1)

        style = ttk.Style()
        style.configure("Browse.TButton", padding=10)

        public_btn = ttk.Button(index_frame, text="Public Files", style="Browse.TButton", command=lambda: self.load_browsed_index(constants.INDEX_NAME_PUBLIC))
        shared_btn = ttk.Button(index_frame, text="Shared Files", style="Browse.TButton", command=lambda: self.load_browsed_index(constants.INDEX_NAME_SHARED))
        paid_btn = ttk.Button(index_frame, text="Paid Files", style="Browse.TButton", command=lambda: self.load_browsed_index(constants.INDEX_NAME_PAID))
        
        public_btn.grid(row=0, column=0, padx=5, sticky="ew")
        shared_btn.grid(row=0, column=1, padx=5, sticky="ew")
        paid_btn.grid(row=0, column=2, padx=5, sticky="ew")

        # File List Display
        list_frame = ttk.LabelFrame(self.content_frame, text="Files", padding="10")
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        self.file_listbox = tk.Listbox(list_frame, font="-size 11")
        self.file_listbox.grid(row=0, column=0, sticky="nsew")

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.file_listbox.configure(yscrollcommand=scrollbar.set)
        
    def load_browsed_index(self, index_name: str):
        self.current_index_name = index_name
        self._set_ui_busy(True, f"Loading '{index_name}' index from {self.browsed_address[:8]}...")
        self.file_listbox.delete(0, tk.END)

        thread = threading.Thread(target=self._load_browsed_index_worker, args=(index_name,))
        thread.daemon = True
        thread.start()

    def _load_browsed_index_worker(self, index_name):
        try:
            is_browsing_self = (self.browsed_address.lower() == self.controller.client.get_logged_in_address().lower())
            index_files = []
            if index_name == constants.INDEX_NAME_PUBLIC:
                index_pointer = self.controller.client.get_master_index_pointer(self.browsed_address, index_name)
                index_meta = self.controller.client.get_file_metadata(index_pointer['fileId'])
                index_blob = self.controller.client.download_from_ipfs(index_meta['ipfsCID'])
                index_data = IndexManager.from_json_bytes(index_blob)
                index_files = index_data.get("files", [])
            else:
                if is_browsing_self:
                    if not self.controller.client.session_master_key:
                        raise exceptions.ClientError("You must be logged in to browse your own encrypted indexes.")

                    index_pointer = self.controller.client.get_master_index_pointer(self.browsed_address, index_name)
                    index_meta = self.controller.client.get_file_metadata(index_pointer['fileId'])
                    index_blob = self.controller.client.download_from_ipfs(index_meta['ipfsCID'])
                    
                    decrypted_index_bytes = crypto.umbral_decrypt_own(self.controller.client.session_umbral_private_key,index_blob)
                    index_data = IndexManager.from_json_bytes(decrypted_index_bytes)
                    index_files = index_data.get("files", [])
                else:
                    index_files = self.controller.client.retrieve_shared_index(self.browsed_address, index_name)
            
            self.after(0, self.on_load_success, index_files)

        except Exception as e:
            self.after(0, self.on_load_error, e)

    def on_load_success(self, file_list):
        self.current_file_list = file_list
        self.file_listbox.delete(0, tk.END)
        if self.current_file_list:
            for file_entry in self.current_file_list:
                display_text = f"ID: {file_entry['fileId']:<5} |   Filename: {file_entry['filename']}"
                self.file_listbox.insert(tk.END, display_text)
            self.status_var.set(f"Successfully loaded {len(self.current_file_list)} file(s).")
        else:
            self.status_var.set(f"This index is empty.")
        self._set_ui_busy(False)
    
    def on_load_error(self, error):
        self.file_listbox.delete(0, tk.END)
        self.status_var.set(f"Error loading index: {error}")
        self._set_ui_busy(False)
        messagebox.showerror("Load Failed", f"Could not load the index.\n\nReason: {error}")

    def handle_view_details(self):
        selected_indices = self.file_listbox.curselection()
        if not selected_indices: return
        self.controller.show_frame("FileDetailsView")