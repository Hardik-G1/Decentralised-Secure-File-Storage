# ui-app/views/file_control_view.py

import tkinter as tk
import traceback
import ttkbootstrap as ttk
from tkinter import messagebox
import threading

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

from client import constants

class FileControlView(tk.Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller
        
        self.shareable_indexes = {} 
        self.pending_requests_for_file = []

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        notebook = ttk.Notebook(self)
        notebook.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.file_requests_tab = ttk.Frame(notebook, padding=15)
        self.index_access_tab = ttk.Frame(notebook, padding=15)

        notebook.add(self.file_requests_tab, text=" Individual File Requests ")
        notebook.add(self.index_access_tab, text=" Index Browse Requests ")
        
        self._create_file_requests_widgets()
        self._create_index_access_widgets()

    def on_show(self):
        self.handle_load_shareable_indexes() 
        self.handle_refresh_index_requests() 


    def _create_file_requests_widgets(self):
        tab = self.file_requests_tab
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(3, weight=1)

        ttk.Label(tab, text="Select Index:", font="-weight bold").grid(row=0, column=0, padx=(0,10), sticky="w")
        self.file_index_var = tk.StringVar()
        self.index_combo = ttk.Combobox(tab, textvariable=self.file_index_var, state="disabled")
        self.index_combo.grid(row=0, column=1, sticky="ew")
        self.index_combo.bind("<<ComboboxSelected>>", self.handle_index_selected_for_files)

        ttk.Label(tab, text="Select File:", font="-weight bold").grid(row=1, column=0, padx=(0,10), sticky="w", pady=(10,0))
        self.file_combo_var = tk.StringVar()
        self.file_combo = ttk.Combobox(tab, textvariable=self.file_combo_var, state="disabled")
        self.file_combo.grid(row=1, column=1, sticky="ew", pady=(10,0))
        self.file_combo.bind("<<ComboboxSelected>>", self.handle_file_selected)

        list_frame = ttk.LabelFrame(tab, text=" 📬 Pending Requests for Selected File ", padding=10)
        list_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(15,0))
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)
        
        listbox_frame = ttk.Frame(list_frame)
        listbox_frame.grid(row=0, column=0, sticky="nsew")
        listbox_frame.grid_columnconfigure(0, weight=1)
        listbox_frame.grid_rowconfigure(0, weight=1)
        
        self.requests_listbox = tk.Listbox(
            listbox_frame,
            font="-size 11",
            selectmode="single",
            activestyle="none",
            bg="#ffffff",
            fg="#333333",
            selectbackground="#0d6efd",
            selectforeground="white",
            relief="flat",
            borderwidth=1,
            highlightthickness=1,
            highlightbackground="#dee2e6",
            highlightcolor="#0d6efd",
            height=6,  # Show 6 items at a time
        )
        
        self.requests_listbox.grid(padx=5, pady=5)
        self.requests_listbox.grid(row=0, column=0, sticky="nsew")
        
        scrollbar = ttk.Scrollbar(listbox_frame, orient="vertical", command=self.requests_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.requests_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.requests_listbox.bind("<<ListboxSelect>>", self.on_request_select)

        action_frame = ttk.Frame(tab)
        action_frame.grid(row=4, column=0, columnspan=2, pady=10)
        self.approve_button = ttk.Button(action_frame, text="Approve", bootstyle="success", state="disabled", command=self.handle_approve)
        self.approve_button.pack(side="left", padx=10)
        self.deny_button = ttk.Button(action_frame, text="Deny", bootstyle="danger", state="disabled", command=self.handle_deny)
        self.deny_button.pack(side="left", padx=10)
        self.status_var_file = tk.StringVar()
        ttk.Label(tab, textvariable=self.status_var_file).grid(row=5, column=0, columnspan=2, pady=5, sticky="w")

    def handle_load_shareable_indexes(self):
        self._set_file_ui_busy(True, "Loading your shareable indexes...")
        self.requests_listbox.delete(0, tk.END)
        self.file_combo.set("")
        self.file_combo['values'] = []
        thread = threading.Thread(target=self._load_shareable_indexes_worker)
        thread.daemon = True; thread.start()

    def _load_shareable_indexes_worker(self):
        try:
            indexes_data = {}
            for index_name in [constants.INDEX_NAME_SHARED, constants.INDEX_NAME_PAID]:
                indexes_data[index_name] = self.controller.client.retrieve_index_content(self.controller.client.get_logged_in_address(), index_name)
            self.after(0, self.on_load_shareable_indexes_success, indexes_data)
        except Exception as e:
            self.after(0, self.on_load_shareable_indexes_error, e)
            
    def on_load_shareable_indexes_success(self, indexes_data):
        self.shareable_indexes = indexes_data
        self.index_combo['values'] = list(self.shareable_indexes.keys())
        self.index_combo.config(state="readonly")
        self.index_combo.set("Select an index to manage...")
        self._set_file_ui_busy(False, "Select an index to see its files.")

    def on_load_shareable_indexes_error(self, error):
        self._set_file_ui_busy(False, f"Error loading your indexes: {error}")

    def handle_index_selected_for_files(self, event=None):
        """Populates the file dropdown based on the selected index."""
        index_name = self.file_index_var.get()
        if not index_name: return
        
        files_in_index = self.shareable_indexes.get(index_name, [])
        self.requests_listbox.delete(0, tk.END)
        if not files_in_index:
            self.file_combo['values'] = [f"No files in '{index_name}' index."]
            self.file_combo.set(f"No files in '{index_name}' index.")
            self.file_combo.config(state="disabled")
        else:
            combo_values = [f"{f['filename']} (ID: {f['fileId']})" for f in files_in_index]
            self.file_combo['values'] = combo_values
            self.file_combo.set("Select a file to manage...")
            self.file_combo.config(state="readonly")
        self.on_request_select() # Disable buttons

    def handle_file_selected(self, event=None):
        selected_index_name = self.file_index_var.get()
        selected_file_idx = self.file_combo.current()
        if selected_index_name not in self.shareable_indexes or selected_file_idx < 0: return
        
        selected_file = self.shareable_indexes[selected_index_name][selected_file_idx]
        file_id = selected_file['fileId']
        
        self._set_file_ui_busy(True, f"Fetching requests for File ID: {file_id}...")
        thread = threading.Thread(target=self._fetch_requests_for_file_worker, args=(file_id,selected_index_name,))
        thread.daemon = True; thread.start()


    def _fetch_requests_for_file_worker(self, file_id,selected_index_name):
        try:
            requests = self.controller.client.get_my_pending_file_requests(file_id,selected_index_name)
            self.after(0, self.on_fetch_requests_success, requests)
        except Exception as e:
            self.after(0, self.on_fetch_requests_error, e)
    def on_fetch_requests_success(self, requests):
        self.pending_requests_for_file = requests
        self.requests_listbox.delete(0, tk.END)
        if not self.pending_requests_for_file:
            self.requests_listbox.insert(tk.END, "  📭  No pending requests for this file")
        else:
            for req in self.pending_requests_for_file:
                formatted_address = f"  👤  {req['requester']}"  
                self.requests_listbox.insert(tk.END, formatted_address)
                
        self.requests_listbox.configure(
            selectmode="single",
            height=6 if self.pending_requests_for_file else 2
        )
        
        self._set_file_ui_busy(False, f"Found {len(requests)} pending request(s).")
    def on_fetch_requests_error(self, error):
        self._set_file_ui_busy(False, f"Error fetching requests: {error}")
    def on_request_select(self, event=None):
        if self.requests_listbox.curselection():
            self.approve_button.config(state="normal")
            if self.file_index_var.get()!="paid":
                self.deny_button.config(state="normal")
        else:
            self.approve_button.config(state="disabled"); self.deny_button.config(state="disabled")
    def handle_approve(self):
        selected_file_idx = self.file_combo.current(); selected_req_indices = self.requests_listbox.curselection()
        index_name = self.file_index_var.get()
        if index_name not in self.shareable_indexes or selected_file_idx < 0 or not selected_req_indices: return
        file_id = self.shareable_indexes[index_name][selected_file_idx]['fileId']
        requester = self.pending_requests_for_file[selected_req_indices[0]]['requester']
        self._set_file_ui_busy(True, f"Approving request for File {file_id}..."); thread = threading.Thread(target=self._approve_file_worker, args=(file_id, requester)); thread.daemon = True; thread.start()
    def _approve_file_worker(self, file_id, requester):
        try:
            self.controller.client.approve_access_request(file_id, requester); self.controller.client.grant_access_to_file(file_id, requester); self.after(0, self.on_file_action_success, "Approval")
        except Exception as e: self.after(0, self.on_file_action_error, "Approval", e)
    def handle_deny(self):
        selected_file_idx = self.file_combo.current(); selected_req_indices = self.requests_listbox.curselection()
        index_name = self.file_index_var.get()
        if index_name not in self.shareable_indexes or selected_file_idx < 0 or not selected_req_indices: return
        file_id = self.shareable_indexes[index_name][selected_file_idx]['fileId']
        requester = self.pending_requests_for_file[selected_req_indices[0]]['requester']
        self._set_file_ui_busy(True, f"Denying request for File {file_id}..."); thread = threading.Thread(target=self._deny_file_worker, args=(file_id, requester)); thread.daemon = True; thread.start()
    def _deny_file_worker(self, file_id, requester):
        try:
            self.controller.client.deny_access_request(file_id, requester); self.after(0, self.on_file_action_success, "Denial")
        except Exception as e: self.after(0, self.on_file_action_error, "Denial", e)
    def on_file_action_success(self, action):
        messagebox.showinfo("Success", f"{action} was successful."); self.handle_file_selected()
    def on_file_action_error(self, action, error):
        self._set_file_ui_busy(False, "")
        error_str=str(error)
        error_s=error
        if "execution" in error_str:
            error_s=error_str.split("execution reverted:")[1].split("'")[0].strip()
        action=f"{action} failed:\n\n"
        messagebox.showerror("Error", f"{action}{error_s}")
    def _set_file_ui_busy(self, is_busy, message=""):
        combo_state = "disabled" if is_busy else "readonly"; self.file_combo.config(state=combo_state); self.index_combo.config(state=combo_state)
        action_button_state = "disabled"
        if not is_busy and self.requests_listbox.curselection(): action_button_state = "normal"
        self.approve_button.config(state=action_button_state); self.deny_button.config(state=action_button_state); self.status_var_file.set(message); self.update_idletasks()


    def _create_index_access_widgets(self):
        tab = self.index_access_tab; tab.grid_columnconfigure(0, weight=1); tab.grid_rowconfigure(1, weight=1)
        top_frame = ttk.Frame(tab)
        top_frame.grid(row=0, column=0, sticky="ew", pady=(0,10))
        
        title_frame = ttk.Frame(top_frame)
        title_frame.pack(side="left")
        ttk.Label(
            title_frame,
            text="📂",  # Folder icon
            font="-size 14"
        ).pack(side="left", padx=(0,5))
        ttk.Label(
            title_frame,
            text="Pending requests from users to browse your indexes",
            font="-size 11 -weight bold"
        ).pack(side="left")

        self.index_refresh_button = ttk.Button(
            top_frame,
            text="↻ Refresh List",
            command=self.handle_refresh_index_requests,
            bootstyle="outline-primary"
        )
        self.index_refresh_button.pack(side="right")

        tree_frame = ttk.Frame(tab)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        style = ttk.Style()
        style.configure("Custom.Treeview",
            background="white",
            fieldbackground="white",
            foreground="#333333",
            rowheight=30
        )
        style.configure("Custom.Treeview.Heading",
            font=("-size 10 -weight bold"),
            padding=5
        )

        self.index_requests_tree = ttk.Treeview(
            tree_frame,
            columns=("Index Name", "Requester"),
            show="headings",
            style="Custom.Treeview",
            selectmode="browse"
        )
        
        self.index_requests_tree.heading("Index Name", text="📁 Index Name")
        self.index_requests_tree.heading("Requester", text="👤 Requester Address")
        
        self.index_requests_tree.column("Index Name", width=200)
        self.index_requests_tree.column("Requester", width=400)
        
        self.index_requests_tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.index_requests_tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.index_requests_tree.configure(yscrollcommand=scrollbar.set)
        
        self.index_requests_tree.bind("<<TreeviewSelect>>", self.on_index_request_select)
        action_frame = ttk.Frame(tab); action_frame.grid(row=2, column=0, pady=10)
        self.approve_index_button = ttk.Button(action_frame, text="Approve Index Access", bootstyle="success", state="disabled", command=self.handle_approve_index); self.approve_index_button.pack(side="left", padx=10)
        self.deny_index_button = ttk.Button(action_frame, text="Deny Index Access", bootstyle="danger", state="disabled", command=self.handle_deny_index); self.deny_index_button.pack(side="left", padx=10)
        self.status_var_index = tk.StringVar(); ttk.Label(tab, textvariable=self.status_var_index).grid(row=3, column=0, pady=5, sticky="w")

    def handle_refresh_index_requests(self):
        self._set_index_ui_busy(True, "Scanning blockchain for index requests...")
        thread = threading.Thread(target=self._generic_worker, args=(self.controller.client.get_my_pending_index_requests, self.on_refresh_index_success, self.on_refresh_index_error))
        thread.daemon = True
        thread.start()
    
    def _refresh_index_requests_worker(self):
        try:
            requests = self.controller.client.get_my_pending_index_requests(); self.after(0, self.on_refresh_index_success, requests)
        except Exception as e: self.after(0, self.on_refresh_index_error, e)
    def on_refresh_index_success(self, requests):
        self.pending_index_requests = requests
        for item in self.index_requests_tree.get_children(): self.index_requests_tree.delete(item)
        if not self.pending_index_requests:
            self.index_requests_tree.insert("", "end", values=("No pending index requests found.", ""))
        else:
            for req in self.pending_index_requests: self.index_requests_tree.insert("", "end", values=(req['indexName'], req['requester']))
        self._set_index_ui_busy(False, f"Found {len(self.pending_index_requests)} pending index request(s).")
    def on_refresh_index_error(self, error): self._set_index_ui_busy(False, f"Error scanning index requests: {error}")
    def on_index_request_select(self, event=None):
        if self.index_requests_tree.selection(): self.approve_index_button.config(state="normal"); self.deny_index_button.config(state="normal")
        else: self.approve_index_button.config(state="disabled"); self.deny_index_button.config(state="disabled")
    def _set_index_ui_busy(self, is_busy, message=""):
        state = "disabled" if is_busy else "normal"; self.approve_index_button.config(state=state); self.deny_index_button.config(state=state); self.index_refresh_button.config(state=state); self.status_var_index.set(message)
        if is_busy: self.update_idletasks()
    def handle_approve_index(self):
        selected_item = self.index_requests_tree.selection();
        if not selected_item: return
        item_values = self.index_requests_tree.item(selected_item[0], "values")
        index_name, requester = item_values[0], item_values[1]
        self._set_index_ui_busy(True, f"Approving request for '{index_name}' index...")
        thread = threading.Thread(target=self._approve_index_worker, args=(index_name, requester)); thread.daemon = True; thread.start()
    def _approve_index_worker(self, index_name, requester):
        try:
            self.controller.client.approve_index_access_request(index_name, requester)
            self.controller.client.grant_index_access(index_name, requester)
            self.after(0, self.on_index_action_success, "Approval")
        except Exception as e: self.after(0, self.on_index_action_error, "Approval", e)
    def handle_deny_index(self):
        selected_item = self.index_requests_tree.selection();
        if not selected_item: return
        item_values = self.index_requests_tree.item(selected_item[0], "values")
        index_name, requester = item_values[0], item_values[1]
        self._set_index_ui_busy(True, f"Denying request for '{index_name}' index...")
        thread = threading.Thread(target=self._deny_index_worker, args=(index_name, requester)); thread.daemon = True; thread.start()
    def _deny_index_worker(self, index_name, requester):
        try:
            self.controller.client.deny_index_access_request(index_name, requester); self.after(0, self.on_index_action_success, "Denial")
        except Exception as e: self.after(0, self.on_index_action_error, "Denial", e)
    def on_index_action_success(self, action):
        messagebox.showinfo("Success", f"Index request {action.lower()} was successful."); self.handle_refresh_index_requests()
    def on_index_action_error(self, action, error):
        self._set_index_ui_busy(False); messagebox.showerror("Error", f"Index request {action.lower()} failed:\n\n{error}")
        traceback_string = traceback.format_exc()
        traceback_string = traceback.format_exc()
        
        detailed_error_message = (
            f"Index request {action.lower()} failed with an unexpected error.\n\n"
            f"Error: {error}\n\n"
            f"--- Technical Details ---\n{traceback_string}"
        )
        messagebox.showerror("Error", detailed_error_message)

    def _generic_worker(self, client_func, success_cb, error_cb):
        try:
            data = client_func()
            self.after(0, success_cb, data)
        except Exception as e:
            self.after(0, error_cb, e)