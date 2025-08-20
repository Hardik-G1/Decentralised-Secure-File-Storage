
import os
import tkinter as tk
import ttkbootstrap as ttk
from tkinter import messagebox
import threading

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from app import App

from client import Web3Client, exceptions

class LoginView(tk.Frame):
    def __init__(self, parent, controller: 'App'):
        super().__init__(parent)
        self.controller = controller
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        main_frame = ttk.Frame(self)
        main_frame.grid(row=0, column=0, sticky="") 
        
        ttk.Frame(main_frame, height=20).pack()  
        
        title_label = ttk.Label(main_frame, text="Connect to Your Wallet", font="-size 16 -weight bold")
        title_label.pack(pady=20)
        
        content_frame = ttk.Frame(main_frame)
        content_frame.pack()

        ttk.Label(content_frame, text="Enter your Wallet Private Key:").pack(pady=(0, 5))
        
        self.pk_var = tk.StringVar()
        self.pk_entry = ttk.Entry(content_frame, textvariable=self.pk_var, width=66, show="*")
        self.pk_entry.pack(pady=(0, 10))


        self.connect_button = ttk.Button(
            content_frame,
            text="Connect",
            command=self.handle_connect,
            width=15,
            bootstyle="primary-outline-toolbutton"  
        )
        self.connect_button.pack(pady=10, ipady=5)  

        self.status_var = tk.StringVar()
        status_label = ttk.Label(content_frame, textvariable=self.status_var, bootstyle="danger") 
        status_label.pack(pady=10)

    def handle_connect(self):
        private_key = self.pk_var.get()
        if not private_key or len(private_key) != 64:
            self.status_var.set("Invalid private key format.")
            return

        self.connect_button.config(state="disabled")
        self.pk_entry.config(state="disabled")
        self.status_var.set("Connecting to blockchain... (This may take a moment)")
        
        thread = threading.Thread(target=self._connect_worker, args=(private_key,))
        thread.daemon = True
        thread.start()

    def _connect_worker(self, private_key):
        try:
            client = Web3Client(
                private_key=private_key,
                rpc_url=os.getenv("POLYGON_AMOY_RPC_URL"),
                contract_address=os.getenv("CONTRACT_ADDRESS"),
                pinata_jwt=os.getenv("PINATA_JWT")
            )
            
            self.after(0, self.on_connect_success, client)

        except (exceptions.ClientError, Exception) as e:
            self.after(0, self.on_connect_error, e)

    def on_connect_success(self, client: Web3Client):
        self.status_var.set(f"Success! Connected as {client.get_logged_in_address()}. Checking user status...")
        self.controller.client = client
        
        self.controller.handle_post_login_flow()
        
        self.connect_button.config(state="normal")
        self.pk_entry.config(state="normal")


    def on_connect_error(self, error: Exception):
        self.status_var.set(f"{error}")
        messagebox.showerror("Connection Failed", f"Could not connect to the client.\n\n{error}")
        
        self.connect_button.config(state="normal")
        self.pk_entry.config(state="normal")
        
    def on_show(self):
        self.pk_var.set("")
        self.status_var.set("")