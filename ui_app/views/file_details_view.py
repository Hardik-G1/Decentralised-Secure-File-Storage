# ui-app/views/file_details_view.py

import tkinter as tk
import ttkbootstrap as ttk
from tkinter import messagebox, filedialog
import threading

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

from client import constants

class FileDetailsView(tk.Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller
        
        self.current_file_meta = None
        self.current_file_id = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1) 

        lookup_frame = ttk.Frame(self, padding=20)
        lookup_frame.grid(row=1, column=0, sticky="ew")
        lookup_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(lookup_frame, text="File ID:").grid(row=0, column=0, padx=(0, 10))
        self.file_id_var = tk.StringVar()
        self.file_id_entry = ttk.Entry(lookup_frame, textvariable=self.file_id_var, width=50)
        self.file_id_entry.grid(row=0, column=1, sticky="ew")
        self.get_info_button = ttk.Button(lookup_frame, text="Get File Info", command=self.handle_get_info)
        self.get_info_button.grid(row=0, column=2, padx=(10, 0))

        details_frame = ttk.LabelFrame(self, text="File Information", padding=15)
        details_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        
        self.details_labels = {}
        info_fields = ["Owner", "Price (MATIC)", "Access Mode", "Encrypted", "Is Index File", "File Type"]
        for i, field in enumerate(info_fields):
            label_title = ttk.Label(details_frame, text=f"{field}:", font="-weight bold")
            label_title.grid(row=i, column=0, sticky="w", padx=5, pady=2)
            
            var = tk.StringVar(value="...")
            label_value = ttk.Label(details_frame, textvariable=var)
            label_value.grid(row=i, column=1, sticky="w", padx=5, pady=2)
            self.details_labels[field] = var
        
        self.action_button = ttk.Button(details_frame, text="...", state="disabled", width=30)
        self.action_button.grid(row=len(info_fields), column=0, columnspan=2, pady=20)

        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        status_bar.grid(row=3, column=0, sticky="ew")

    def on_show(self, file_id=None):
        self._reset_view()
        if file_id:
            self.file_id_var.set(str(file_id))
            self.handle_get_info()

    def _reset_view(self):
        self.file_id_var.set("")
        self.status_var.set("Enter a File ID to look up its details.")
        for var in self.details_labels.values():
            var.set("...")
        self.action_button.config(text="...", state="disabled", command=lambda: None)
        self.current_file_meta = None
        self.current_file_id = None
        self._set_ui_busy(False)

    def _set_ui_busy(self, is_busy, message=""):
        state = "disabled" if is_busy else "normal"
        self.file_id_entry.config(state=state)
        self.get_info_button.config(state=state)
        if is_busy:
            self.action_button.config(state="disabled")
            self.status_var.set(message)
            self.update_idletasks()
        else:
            self.status_var.set(message if message else "Ready.")

    def handle_get_info(self):
        try:
            file_id = int(self.file_id_var.get())
        except (ValueError, TypeError):
            messagebox.showerror("Invalid Input", "File ID must be a number.")
            return

        self._set_ui_busy(True, f"Fetching metadata for File ID: {file_id}...")
        thread = threading.Thread(target=self._get_info_worker, args=(file_id,))
        thread.daemon = True
        thread.start()

    def _get_info_worker(self, file_id):
        try:
            meta = self.controller.client.get_file_metadata(file_id)
            is_deleted=meta['isDeleted']
            if is_deleted:
                self.after(0,self.on_get_info_error,"File is deleted!")
                return
            has_access = self.controller.client.check_access_rights(file_id, self.controller.client.get_logged_in_address())
            self.after(0, self.on_get_info_success, meta, has_access, file_id)
        except Exception as e:
            self.after(0, self.on_get_info_error, e)

    def on_get_info_success(self, meta, has_access, file_id):
        self.current_file_meta = meta
        self.current_file_id = file_id
        is_owner = (meta['owner'].lower() == self.controller.client.get_logged_in_address().lower())

        self.details_labels["Owner"].set(meta['owner'])
        price_in_eth = self.controller.client.w3.from_wei(meta['price'], 'ether')
        self.details_labels["Price (MATIC)"].set(f"{price_in_eth}" if meta['price'] > 0 else "Free")
        self.details_labels["Access Mode"].set(constants.AccessMode(meta['mode']).name)
        self.details_labels["Encrypted"].set(str(meta['isEncrypted']))
        self.details_labels["Is Index File"].set(str(meta['isIndex']))
        self.details_labels["File Type"].set(meta['fileExtension'])
        
        self.status_var.set("Metadata loaded. Access status determined.")
        
        if is_owner or has_access:
            self.action_button.config(text="Download", state="normal", command=self.handle_download, bootstyle="success")
        elif meta['mode'] == constants.AccessMode.PAID:
            self.action_button.config(text=f"Purchase for {price_in_eth} MATIC", state="normal", command=self.handle_purchase, bootstyle="success")
        elif meta['mode'] == constants.AccessMode.SHARED:
            if meta['isIndex']:
                 self.action_button.config(text="Request Index Access (Browse)", state="normal", command=self.handle_request_index_access, bootstyle="primary")
            else:
                 self.action_button.config(text="Request File Access (Download)", state="normal", command=self.handle_request_file_access, bootstyle="primary")
        elif meta['mode'] == constants.AccessMode.PUBLIC and not meta['isEncrypted']:
             self.action_button.config(text="Download", state="normal", command=self.handle_download, bootstyle="success")
        else:
            self.action_button.config(text="Access Denied", state="disabled", bootstyle="secondary")
        
        self._set_ui_busy(False)

    def on_get_info_error(self, error):
        self._reset_view()
        self.status_var.set(f"{error}")

    
    def handle_download(self):
        self._set_ui_busy(True, f"Starting download for File ID: {self.current_file_id}...")
        thread = threading.Thread(target=self._download_worker)
        thread.daemon = True
        thread.start()

    def _download_worker(self):
        try:
            decrypted_content = self.controller.client.retrieve_and_decrypt_shared_file(self.current_file_id)
            self.after(0, self.on_download_success, decrypted_content)
        except Exception as e:
            self.after(0, self.on_action_error, "Download", e)

    def on_download_success(self, decrypted_content):
        filename = f"file_{self.current_file_id}.{self.current_file_meta.get('fileExtension', 'bin')}"
        save_path = filedialog.asksaveasfilename(initialfile=filename)
        if save_path:
            with open(save_path, 'wb') as f: f.write(decrypted_content)
            messagebox.showinfo("Download Complete", f"File saved to:\n{save_path}")
        self.status_var.set("Download complete.")
        self._set_ui_busy(False)

    def handle_purchase(self):
        price_in_eth = self.controller.client.w3.from_wei(self.current_file_meta['price'], 'ether')
        if not messagebox.askyesno("Confirm Purchase", f"Do you want to purchase File ID {self.current_file_id} for {price_in_eth} MATIC?"):
            return
        
        self._set_ui_busy(True, f"Processing purchase for File ID: {self.current_file_id}...")
        thread = threading.Thread(target=self._purchase_worker)
        thread.daemon = True
        thread.start()
        
    def _purchase_worker(self):
        try:
            self.controller.client.purchase_file(self.current_file_id, self.current_file_meta['price'])
            self.after(0, self.on_action_success, "Purchase")
        except Exception as e:
            self.after(0, self.on_action_error, "Purchase", e)

    def handle_request_file_access(self):
        self._set_ui_busy(True, f"Sending access request for File ID: {self.current_file_id}...")
        thread = threading.Thread(target=self._request_file_worker)
        thread.daemon = True
        thread.start()

    def _request_file_worker(self):
        try:
            self.controller.client.request_access(self.current_file_id)
            self.after(0, self.on_action_success, "File access request")
        except Exception as e:
            self.after(0, self.on_action_error, "File access request", e)
            
    def handle_request_index_access(self):
        self._set_ui_busy(True, f"Sending access request for index...")
        thread = threading.Thread(target=self._request_index_worker)
        thread.daemon = True
        thread.start()

    def _request_index_worker(self):
        try:
            owner = self.current_file_meta['owner']
            index_name_to_request = constants.INDEX_NAME_SHARED
            
            self.controller.client.request_index_access(owner, index_name_to_request)
            self.after(0, self.on_action_success, f"'{index_name_to_request}' index access request")
        except Exception as e:
            self.after(0, self.on_action_error, "Index access request", e)

    def on_action_success(self, action_name):
        self.status_var.set(f"{action_name} successful! Refresh to see updated status.")
        messagebox.showinfo("Success", f"{action_name} was successful. The owner has been notified.")
        self._set_ui_busy(False)
        self.handle_get_info() # Refresh the view

    def on_action_error(self, action_name, error):
        self.status_var.set(f"{action_name} failed: {error}")
        self._set_ui_busy(False)
        error_str = str(error)
        if "execution" in error_str:
            meaningful_msg = error_str.split("execution reverted:")[1].split("'")[0].strip()
            self.status_var.set(meaningful_msg)
        else:
            self.status_var.set(error)