# ui-app/app.py

import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

from views.login_view import LoginView
from views.create_shares_view import CreateSharesView
from views.reconstruct_key_view import ReconstructKeyView
from views.dashboard_view import DashboardView
from views.upload_view import UploadView
from views.file_control_view import FileControlView
from views.file_details_view import FileDetailsView
from views.browse_others_view import BrowseOthersView
from views.settings_view import SettingsView
from client import Web3Client, ClientError

class App(ttk.Window):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, themename="united")
        self.title("Decentralized Secure File Storage")
        self.geometry("1024x950")

        self.client: Web3Client | None = None


        self.menu_bar = ttk.Frame(self, style="primary.TFrame")
        
        ttk.Button(self.menu_bar, text="My Files", command=lambda: self.show_frame("DashboardView")).pack(side="left", padx=5)
        ttk.Button(self.menu_bar, text="Upload", command=lambda: self.show_frame("UploadView")).pack(side="left", padx=5)
        ttk.Button(self.menu_bar, text="File Control", command=lambda: self.show_frame("FileControlView")).pack(side="left", padx=5)
        ttk.Button(self.menu_bar, text="File Details", command=lambda: self.show_frame("FileDetailsView")).pack(side="left", padx=5)
        ttk.Button(self.menu_bar, text="Browse Others", command=lambda: self.show_frame("BrowseOthersView")).pack(side="left", padx=5)
        ttk.Button(self.menu_bar, text="Settings", command=lambda: self.show_frame("SettingsView")).pack(side="left", padx=5)
        # ttk.Button(self.menu_bar, text="History", command=lambda: self.show_frame("HistoryView")).pack(side="left", padx=5)

        ttk.Button(self.menu_bar, text="Logout", command=self.logout).pack(side="right", padx=5)

        container = ttk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (LoginView, CreateSharesView, ReconstructKeyView, DashboardView, UploadView,FileControlView, FileDetailsView,BrowseOthersView,SettingsView):
            page_name = F.__name__
            frame = F(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("LoginView")

    def show_frame(self, page_name: str):
        is_logged_in_view = page_name in ["DashboardView", "UploadView", "FileDetailsView","FileControlView","BrowseOthersView","SettingsView"] # Add other logged-in views here

        if is_logged_in_view:
            if not self.menu_bar.winfo_ismapped():
                self.menu_bar.pack(side="top", fill="x", before=self.frames[page_name].master)
        else:
            if self.menu_bar.winfo_ismapped():
                self.menu_bar.pack_forget()

        frame = self.frames[page_name]
        if hasattr(frame, 'on_show'):
            frame.on_show()
        frame.tkraise()

    def logout(self):
        self.client = None
        print("User logged out. Client instance destroyed.")
        self.show_frame("LoginView") # This will automatically hide the menu bar now

    def handle_post_login_flow(self):
        if not self.client:
            self.show_frame("LoginView")
            return
        try:
            is_new_user = self.client.is_first_time_user()
            if is_new_user:
                print("New user detected. Transitioning to CreateSharesView.")
                self.show_frame("CreateSharesView")
            else:
                print("Returning user detected. Transitioning to ReconstructKeyView.")
                self.show_frame("ReconstructKeyView")
        except ClientError as e:
            print(f"Error in post-login flow: {e}")
            login_frame = self.frames["LoginView"]
            login_frame.status_var.set(f"Error checking user status: {e}")
            self.show_frame("LoginView")
