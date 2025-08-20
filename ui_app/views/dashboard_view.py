# ui-app/views/dashboard_view.py

import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox
import threading 
import hashlib

from client import constants, crypto
from client.exceptions import ClientError, IndexManagementError
from client.offchain.index_manager import IndexManager

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

class DashboardView(tk.Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller
        
        self.current_file_list = []
        self.current_index_name = ""
        self.index_cache = {}

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(1, weight=1)

        action_bar = ttk.Frame(self, padding=(10, 10, 10, 5), style="Primary.TFrame")
        action_bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        
        style = ttk.Style()
        style.configure("Primary.TFrame", background="#2b3d4f")

        nav_panel = ttk.Frame(self, width=200, padding=(10, 5, 10, 10))
        nav_panel.grid(row=1, column=0, sticky="nsw")

        ttk.Label(nav_panel, text="My Indexes", font="-size 12 -weight bold").pack(pady=(0, 10), anchor="w")
        
        # Button styles for different sections
        button_styles = {
            constants.INDEX_NAME_PRIVATE: "success-outline-toolbutton",
            constants.INDEX_NAME_PUBLIC: "info-outline-toolbutton",
            constants.INDEX_NAME_SHARED: "warning-outline-toolbutton",
            constants.INDEX_NAME_PAID: "primary-outline-toolbutton"
        }
        
        self.nav_buttons = {}
        for name in [constants.INDEX_NAME_PRIVATE, constants.INDEX_NAME_PUBLIC, constants.INDEX_NAME_SHARED, constants.INDEX_NAME_PAID]:
            btn = ttk.Button(
                nav_panel,
                text=f"📁 {name.capitalize()} Files",
                bootstyle=button_styles[name],
                command=lambda n=name: self.load_index(n)
            )
            btn.pack(fill="x", pady=2)
            self.nav_buttons[name] = btn
            
        ttk.Separator(nav_panel, orient="horizontal").pack(fill="x", pady=10)
        
        self.refresh_button = ttk.Button(
            nav_panel,
            text="↻ Refresh",
            command=self.handle_refresh,
            bootstyle="secondary"
        )
        self.refresh_button.pack(fill="x", pady=2)

        main_content_frame = ttk.Frame(self, padding=(0, 5, 10, 10))
        main_content_frame.grid(row=1, column=1, sticky="nsew")
        main_content_frame.grid_rowconfigure(0, weight=1)
        main_content_frame.grid_columnconfigure(0, weight=1)
        
        list_frame = ttk.LabelFrame(main_content_frame, text="Files", padding="10")
        list_frame.grid(row=0, column=0, sticky="nsew")
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        self.file_listbox = tk.Listbox(
            list_frame,
            font="-size 11",
            selectmode=tk.SINGLE,
            activestyle='none',  # Remove default selection underline
            borderwidth=0,  # Remove border
            highlightthickness=0,  # Remove highlight border
            bg='#f5f5f5'  # Light gray background
        )
        self.file_listbox.grid(row=0, column=0, sticky="nsew")
        self.file_listbox.bind("<<ListboxSelect>>", self.on_file_select)

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.file_listbox.configure(yscrollcommand=scrollbar.set)

        actions_frame = ttk.Frame(main_content_frame, padding=(10, 0, 0, 0))
        actions_frame.grid(row=0, column=1, sticky="n")

        self.download_button = ttk.Button(
            actions_frame,
            text="⬇ Download",
            state="disabled",
            command=self.handle_download,
            bootstyle="success"
        )
        self.download_button.pack(pady=5, fill="x", ipady=8)
        
        self.delete_button = ttk.Button(
            actions_frame,
            text="🗑 Delete",
            state="disabled",
            command=self.handle_delete,
            bootstyle="danger"
        )
        self.delete_button.pack(pady=5, fill="x", ipady=8)
        
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        status_bar.grid(row=2, column=0, columnspan=2, sticky="ew")
        
    def _set_ui_busy(self, is_busy, message=""):
        state = "disabled" if is_busy else "normal"
        for btn in self.nav_buttons.values():
            btn.config(state=state)
        self.refresh_button.config(state=state)
        if is_busy:
            self.status_var.set(message)
            self.update_idletasks()

    def on_show(self):
        self.index_cache = {}
        if self.controller.client:
            self.load_index(constants.INDEX_NAME_PRIVATE, force_refresh=True)
        else:
            self.welcome_var.set("❌ Not logged in")
            self.file_listbox.delete(0, tk.END)

    def on_file_select(self, event=None):
        if self.file_listbox.curselection():
            self.download_button.config(state="normal")
            self.delete_button.config(state="normal")
        else:
            self.download_button.config(state="disabled")
            self.delete_button.config(state="disabled")

    def handle_refresh(self):
        if self.current_index_name:
            self.load_index(self.current_index_name, force_refresh=True)

    def _populate_listbox(self, file_list):
        self.file_listbox.delete(0, tk.END)
        self.current_file_list = file_list
        
        self.file_listbox.configure(
            selectbackground='#0078d4',  # Microsoft blue for selection
            selectforeground='white'
        )
        
        if self.current_file_list:
            for idx, file_entry in enumerate(self.current_file_list):
                bg_color = '#f0f0f0' if idx % 2 == 0 else '#ffffff'
                
                icon = "📄"  # Default file icon
                if "." in file_entry['filename']:
                    ext = file_entry['filename'].split(".")[-1].lower()
                    if ext in ['pdf']: icon = "📕"
                    elif ext in ['jpg', 'jpeg', 'png', 'gif']: icon = "🖼"
                    elif ext in ['doc', 'docx']: icon = "📝"
                    elif ext in ['xls', 'xlsx']: icon = "📊"
                    elif ext in ['zip', 'rar']: icon = "📦"
                    else: icon="📦"
                
                display_text = f"{icon}  {file_entry['filename']}  (ID: {file_entry['fileId']})"
                self.file_listbox.insert(tk.END, display_text)
                self.file_listbox.itemconfig(idx, bg=bg_color)
        
        self.on_file_select()

    def load_index(self, index_name: str, force_refresh: bool = False):
        self.current_index_name = index_name
        self._set_ui_busy(True, f"Loading '{index_name}' index...")

        button_styles = {
            constants.INDEX_NAME_PRIVATE: ("success-outline-toolbutton", "success"),
            constants.INDEX_NAME_PUBLIC: ("info-outline-toolbutton", "info"),
            constants.INDEX_NAME_SHARED: ("warning-outline-toolbutton", "warning"),
            constants.INDEX_NAME_PAID: ("primary-outline-toolbutton", "primary")
        }
        
        for name, btn in self.nav_buttons.items():
            outline_style, solid_style = button_styles[name]
            btn.configure(bootstyle=solid_style if name == index_name else outline_style)

        if not force_refresh and index_name in self.index_cache:
            self.after(0, self.on_load_index_success, self.index_cache[index_name])
            return

        thread = threading.Thread(target=self._load_index_worker, args=(index_name,))
        thread.daemon = True
        thread.start()

    def _load_index_worker(self, index_name):
        try:
            if not self.controller.client or not self.controller.client.session_master_key:
                raise ClientError("Client is not logged in.")
            
            index_pointer = self.controller.client.get_master_index_pointer(self.controller.client.get_logged_in_address(), index_name)
            if index_pointer['fileId'] == 0:
                self.after(0, self.on_load_index_success, {"files": []})
                return
            
            index_metadata = self.controller.client.get_file_metadata(index_pointer['fileId'])
            encrypted_index_blob = self.controller.client.download_from_ipfs(index_metadata['ipfsCID'])
            
            if hashlib.sha256(encrypted_index_blob).digest() != index_pointer['integrityHash']:
                raise IndexManagementError("Integrity check failed!")
            index_data=None
            if index_name==constants.INDEX_NAME_PUBLIC:
                index_data=IndexManager.from_json_bytes(encrypted_index_blob)
            else:
                decrypted_index_bytes = crypto.decrypt_data(encrypted_index_blob, self.controller.client.session_master_key)
                index_data = IndexManager.from_json_bytes(decrypted_index_bytes)
            
            self.index_cache[index_name] = index_data
            self.after(0, self.on_load_index_success, index_data)

        except Exception as e:
            self.after(0, self.on_load_index_error, e)

    def on_load_index_success(self, index_data):
        self._populate_listbox(index_data.get("files", []))
        self.status_var.set(f"Successfully loaded {len(index_data.get('files', []))} file(s) from '{self.current_index_name}' index.")
        self._set_ui_busy(False)

    def on_load_index_error(self, error):
        self.status_var.set(f"Failed to load index '{self.current_index_name}': {error}")
        self._set_ui_busy(False)
        messagebox.showerror("Error Loading Index", f"{error}")

    def handle_download(self):
        selected_indices = self.file_listbox.curselection()
        if not selected_indices: return
        
        selected_file_entry = self.current_file_list[selected_indices[0]]
        self._set_ui_busy(True, f"Downloading '{selected_file_entry['filename']}'...")
        
        thread = threading.Thread(target=self._download_worker, args=(selected_file_entry,))
        thread.daemon = True
        thread.start()
        
    def _download_worker(self, file_entry):
        try:
            file_id = file_entry['fileId']
            filename = file_entry['filename']
            
            file_meta = self.controller.client.get_file_metadata(file_id)
            is_deleted=file_meta['isDeleted']
            if is_deleted:
                self.after(0,self.on_download_error,"File is deleted!")
                return
            encrypted_content = self.controller.client.download_from_ipfs(file_meta['ipfsCID'])
            
            decrypted_content = None
            if file_meta['isEncrypted']:
                encrypted_key = self.controller.client.get_my_encrypted_key(file_id)
                original_file_key = crypto.decrypt_data(encrypted_key, self.controller.client.session_master_key)
                decrypted_content = crypto.decrypt_data(encrypted_content, original_file_key)
            else:
                decrypted_content = encrypted_content
            
            self.after(0, self.on_download_success, decrypted_content, file_meta,filename)
        except Exception as e:
            self.after(0, self.on_download_error, e)

    def on_download_success(self, decrypted_content, file_meta,filename):
        save_path = filedialog.asksaveasfilename(initialfile=filename, defaultextension=f".{file_meta['fileExtension']}")
        if save_path:
            with open(save_path, 'wb') as f: f.write(decrypted_content)
            self.status_var.set(f"Successfully downloaded and saved '{filename}'.")
            messagebox.showinfo("Download Complete", f"File saved to:\n{save_path}")
        else:
            self.status_var.set("Download cancelled.")
        self._set_ui_busy(False)

    def on_download_error(self, error):
        self.status_var.set(f"Download failed: {error}")
        self._set_ui_busy(False)
        messagebox.showerror("Download Error", f"{error}")
        
    def handle_delete(self):
        selected_indices = self.file_listbox.curselection()
        if not selected_indices: return
            
        selected_file_entry = self.current_file_list[selected_indices[0]]
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{selected_file_entry['filename']}'?"):
            return
        
        self._set_ui_busy(True, f"Deleting '{selected_file_entry['filename']}'...")
        
        thread = threading.Thread(target=self._delete_worker, args=(selected_file_entry,))
        thread.daemon = True
        thread.start()

    def _delete_worker(self, file_entry):
        try:
            file_id = file_entry['fileId']
            self.controller.client.remove_file_from_my_index(file_id, self.current_index_name)
            self.after(0, self.on_delete_success, file_entry['filename'])
        except Exception as e:
            self.after(0, self.on_delete_error, e)

    def on_delete_success(self, filename):
        self.status_var.set(f"Successfully deleted '{filename}'. Refreshing index...")
        self._set_ui_busy(False)
        messagebox.showinfo("Success", f"'{filename}' has been deleted.")
        self.load_index(self.current_index_name, force_refresh=True)

    def on_delete_error(self, error):
        self.status_var.set(f"Delete failed: {error}")
        self._set_ui_busy(False)
        messagebox.showerror("Delete Error", f"{error}")