# ui-app/views/upload_view.py

import os
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog, messagebox
import threading

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

from client import constants
from client.exceptions import ClientError

class UploadView(tk.Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller
        
        self.filepath_var = tk.StringVar()
        self.filename_var = tk.StringVar()
        self.index_var = tk.StringVar()
        self.price_var = tk.StringVar(value="0")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)


        content_frame = ttk.Frame(self, padding=20)
        content_frame.grid(row=1, column=0, sticky="nsew")
        content_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(content_frame, text="File to Upload:").grid(row=0, column=0, sticky="w", pady=5)
        file_entry_frame = ttk.Frame(content_frame)
        file_entry_frame.grid(row=0, column=1, sticky="ew", pady=5)
        file_entry_frame.grid_columnconfigure(0, weight=1)
        self.file_entry = ttk.Entry(file_entry_frame, textvariable=self.filepath_var, state="readonly")
        self.file_entry.grid(row=0, column=0, sticky="ew")
        browse_button = ttk.Button(file_entry_frame, text="Browse...", command=self.select_file)
        browse_button.grid(row=0, column=1, padx=(5, 0))

        ttk.Label(content_frame, text="Display Name:").grid(row=1, column=0, sticky="w", pady=5)
        self.filename_entry = ttk.Entry(content_frame, textvariable=self.filename_var)
        self.filename_entry.grid(row=1, column=1, sticky="ew", pady=5)

        ttk.Label(content_frame, text="Target Index:").grid(row=2, column=0, sticky="w", pady=5)

        self.index_var.set(constants.INDEX_NAME_PUBLIC)
        self.index_frame = ttk.Frame(content_frame)
        self.index_frame.grid(row=2, column=1, sticky="w", pady=5)

        for index_name in [
            constants.INDEX_NAME_PRIVATE,
            constants.INDEX_NAME_PUBLIC,
            constants.INDEX_NAME_SHARED,
            constants.INDEX_NAME_PAID
        ]:
            rb = ttk.Radiobutton(
                self.index_frame,
                text=index_name,
                variable=self.index_var,
                value=index_name,
                command=self.on_index_select
            )
            rb.pack(side="left", padx=5)

        self.price_label = ttk.Label(content_frame, text="Price (in MATIC):")
        self.price_label.grid(row=3, column=0, sticky="w", pady=5)
        self.price_entry = ttk.Entry(content_frame, textvariable=self.price_var, state="disabled")
        self.price_entry.grid(row=3, column=1, sticky="ew", pady=5)

        self.upload_button = ttk.Button(content_frame, text="Start Upload", style="success.TButton", command=self.handle_upload)
        self.upload_button.grid(row=5, column=1, sticky="e", pady=20)
        
        log_frame = ttk.LabelFrame(self, text="Upload Progress", padding="10")
        log_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        log_frame.grid_rowconfigure(1, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.progress_bar = ttk.Progressbar(log_frame, mode='determinate')
        self.progress_bar.grid(row=0, column=0, sticky="ew", pady=(0, 5))

        self.log_text = tk.Text(log_frame, height=10, state="disabled", wrap="word")
        self.log_text.grid(row=1, column=0, sticky="nsew")

    def on_show(self):
        self.filepath_var.set("")
        self.filename_var.set("")
        self.index_var.set(constants.INDEX_NAME_PUBLIC)
        self.on_index_select()
        self.price_var.set("0")
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state="disabled")
        self.progress_bar['value'] = 0
        self._toggle_form_state("normal") # Ensure form is enabled

    def select_file(self):
        filepath = filedialog.askopenfilename(title="Select a file to upload")
        if filepath:
            self.filepath_var.set(filepath)
            # Auto-populate the display name with the file's actual name
            self.filename_var.set(os.path.basename(filepath))

    def on_index_select(self):
        if self.index_var.get() == constants.INDEX_NAME_PAID:
            self.price_label.grid(row=3, column=0, sticky="w", pady=5)
            self.price_entry.grid(row=3, column=1, sticky="ew", pady=5)
        else:
            self.price_label.grid_remove()
            self.price_entry.grid_remove()

    def _toggle_form_state(self, state="disabled"):
        widgets = [self.file_entry, self.filename_entry, self.price_entry, self.upload_button]
        for widget in widgets:
            widget.config(state=state)

        for child in self.index_frame.winfo_children():
            child.config(state=state)
    def handle_upload(self):
        filepath = self.filepath_var.get()
        filename = self.filename_var.get()
        index_name = self.index_var.get()
        price_str = self.price_var.get()

        if not all([filepath, filename, index_name]):
            messagebox.showerror("Input Error", "Please select a file, provide a display name, and choose an index.")
            return

        price_in_wei = 0
        if index_name == constants.INDEX_NAME_PAID:
            try:
                price_in_eth = float(price_str)
                if price_in_eth <= 0: raise ValueError
                price_in_wei = self.controller.client.w3.to_wei(price_in_eth, 'ether')
            except (ValueError, TypeError):
                messagebox.showerror("Input Error", "Please enter a valid, positive price for a PAID file.")
                return

        self._toggle_form_state("disabled")
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.insert(tk.END, "Starting upload...\n")
        self.log_text.config(state="disabled")
        self.progress_bar['value'] = 0

        thread = threading.Thread(
            target=self._upload_worker,
            args=(filepath, filename, index_name, price_in_wei)
        )
        thread.daemon = True
        thread.start()

    def _upload_worker(self, filepath, filename, index_name, price_in_wei):
        try:
            if index_name == constants.INDEX_NAME_PRIVATE:
                self.controller.client.add_new_file(filepath, filename,index_name,price_in_wei)
            else:
                self.controller.client.add_new_file(filepath, filename, index_name, price_in_wei)
            
            self.after(0, self.on_upload_success, filename)
        except Exception as e:
            self.after(0, self.on_upload_error, e)

    def on_upload_success(self, filename):
        self.progress_bar['value'] = 100
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, f"\nSUCCESS: File '{filename}' was uploaded and registered successfully!")
        self.log_text.config(state="disabled")
        messagebox.showinfo("Upload Complete", f"'{filename}' has been successfully uploaded.")
        self._toggle_form_state("normal")
        self.on_show() # Reset form for next upload

    def on_upload_error(self, error):
        self.progress_bar['value'] = 0
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, f"\nERROR: {error}")
        self.log_text.config(state="disabled")
        messagebox.showerror("Upload Failed", f"An error occurred during the upload process:\n\n{error}")
        self._toggle_form_state("normal")