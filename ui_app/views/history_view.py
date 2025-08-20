## Could be a future update for the keeping track of user actions and requests


# # ui-app/views/history_view.py

# import tkinter as tk
# import ttkbootstrap as ttk
# from tkinter import messagebox
# import threading

# from typing import TYPE_CHECKING
# if TYPE_CHECKING:
#     from app import App

# class HistoryView(tk.Frame):
#     def __init__(self, parent, controller: 'App'):
#         super().__init__(parent)
#         self.controller = controller

#         self.grid_rowconfigure(0, weight=1)
#         self.grid_columnconfigure(0, weight=1)
        
#         notebook = ttk.Notebook(self)
#         notebook.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

#         self.file_requests_tab = ttk.Frame(notebook, padding=15)
#         self.index_requests_tab = ttk.Frame(notebook, padding=15)
#         self.purchases_tab = ttk.Frame(notebook, padding=15)
#         self.sales_tab = ttk.Frame(notebook, padding=15)

#         notebook.add(self.file_requests_tab, text=" My Outgoing File Requests ")
#         notebook.add(self.index_requests_tab, text=" My Outgoing Index Requests ")
#         notebook.add(self.purchases_tab, text=" My Purchases ")
#         notebook.add(self.sales_tab, text=" My Sales ")
        
#         self._create_tab(self.file_requests_tab, 
#                          "Files you have requested from other users.", 
#                          ("File ID", "Owner", "Status"),
#                          self.handle_refresh_file_requests)
        
#         self._create_tab(self.index_requests_tab,
#                          "Indexes you have requested to browse from other users.",
#                          ("Owner", "Index Name", "Status"),
#                          self.handle_refresh_index_requests)

#         self._create_tab(self.purchases_tab,
#                          "Files you have successfully purchased.",
#                          ("File ID", "Price (MATIC)"),
#                          self.handle_refresh_purchases)

#         self._create_tab(self.sales_tab,
#                          "Files you have successfully sold to others.",
#                          ("File ID", "Buyer", "Price (MATIC)"),
#                          self.handle_refresh_sales)

#     def on_show(self):
#         self.handle_refresh_file_requests()
#         self.handle_refresh_index_requests()
#         self.handle_refresh_purchases()
#         self.handle_refresh_sales()

#     def _create_tab(self, tab, description, columns, refresh_command):
#         tab.grid_columnconfigure(0, weight=1)
#         tab.grid_rowconfigure(1, weight=1)
        
#         top_frame = ttk.Frame(tab)
#         top_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
#         ttk.Label(top_frame, text=description, font="-size 11").pack(side="left")
        
#         refresh_btn = ttk.Button(top_frame, text="Refresh", command=refresh_command)
#         refresh_btn.pack(side="right")
        
#         tree = ttk.Treeview(tab, columns=columns, show="headings")
#         for col in columns:
#             tree.heading(col, text=col)
#         tree.grid(row=1, column=0, sticky="nsew")
        
#         status_var = tk.StringVar()
#         ttk.Label(tab, textvariable=status_var).grid(row=2, column=0, pady=5, sticky="w")
        
#         # Store the widgets on the instance for later access
#         tab.refresh_btn = refresh_btn
#         tab.tree = tree
#         tab.status_var = status_var

#     def _generic_worker(self, client_func, success_cb, error_cb):
#         try:
#             data = client_func()
#             self.after(0, success_cb, data)
#         except Exception as e:
#             self.after(0, error_cb, e)

#     def handle_refresh_file_requests(self):
#         self._set_busy_state(self.file_requests_tab, True, "Scanning for your outgoing file requests...")
#         thread = threading.Thread(target=self._generic_worker, args=(self.controller.client.get_my_outgoing_file_requests, self.on_file_requests_success, self.on_file_requests_error))
#         thread.daemon = True; thread.start()

#     def on_file_requests_success(self, data):
#         tree = self.file_requests_tab.tree
#         for item in tree.get_children(): tree.delete(item)
#         if not data:
#             tree.insert("", "end", values=("No outgoing file requests found.", "", ""))
#         else:
#             for item in data: tree.insert("", "end", values=(item['fileId'], item['owner'], item['status']))
#         self._set_busy_state(self.file_requests_tab, False, f"Found {len(data)} request(s).")

#     def on_file_requests_error(self, error):
#         self._set_busy_state(self.file_requests_tab, False, f"Error: {error}")

#     def handle_refresh_index_requests(self):
#         self._set_busy_state(self.index_requests_tab, True, "Scanning for your outgoing index requests...")
#         thread = threading.Thread(target=self._generic_worker, args=(self.controller.client.get_my_outgoing_index_requests, self.on_index_requests_success, self.on_index_requests_error))
#         thread.daemon = True; thread.start()

#     def on_index_requests_success(self, data):
#         tree = self.index_requests_tab.tree
#         for item in tree.get_children(): tree.delete(item)
#         if not data:
#             tree.insert("", "end", values=("No outgoing index requests found.", "", ""))
#         else:
#             for item in data: tree.insert("", "end", values=(item['owner'], item['indexName'], item['status']))
#         self._set_busy_state(self.index_requests_tab, False, f"Found {len(data)} request(s).")
        
#     def on_index_requests_error(self, error):
#         self._set_busy_state(self.index_requests_tab, False, f"Error: {error}")
        
#     def handle_refresh_purchases(self):
#         self._set_busy_state(self.purchases_tab, True, "Scanning for your purchases...")
#         thread = threading.Thread(target=self._generic_worker, args=(self.controller.client.get_my_purchases, self.on_purchases_success, self.on_purchases_error))
#         thread.daemon = True; thread.start()
        
#     def on_purchases_success(self, data):
#         tree = self.purchases_tab.tree
#         for item in tree.get_children(): tree.delete(item)
#         if not data:
#             tree.insert("", "end", values=("No purchase history found.", ""))
#         else:
#             for item in data:
#                 price_eth = self.controller.client.w3.from_wei(item['price'], 'ether')
#                 tree.insert("", "end", values=(item['fileId'], f"{price_eth}"))
#         self._set_busy_state(self.purchases_tab, False, f"Found {len(data)} purchase(s).")

#     def on_purchases_error(self, error):
#         self._set_busy_state(self.purchases_tab, False, f"Error: {error}")
        
#     def handle_refresh_sales(self):
#         self._set_busy_state(self.sales_tab, True, "Scanning for your sales...")
#         thread = threading.Thread(target=self._generic_worker, args=(self.controller.client.get_my_sales, self.on_sales_success, self.on_sales_error))
#         thread.daemon = True; thread.start()
        
#     def on_sales_success(self, data):
#         tree = self.sales_tab.tree
#         for item in tree.get_children(): tree.delete(item)
#         if not data:
#             tree.insert("", "end", values=("No sales history found.", "", ""))
#         else:
#             for item in data:
#                 price_eth = self.controller.client.w3.from_wei(item['price'], 'ether')
#                 tree.insert("", "end", values=(item['fileId'], item['buyer'], f"{price_eth}"))
#         self._set_busy_state(self.sales_tab, False, f"Found {len(data)} sale(s).")

#     def on_sales_error(self, error):
#         self._set_busy_state(self.sales_tab, False, f"Error: {error}")
        
#     def _set_busy_state(self, tab, is_busy, msg):
#         tab.refresh_btn.config(state="disabled" if is_busy else "normal")
#         tab.status_var.set(msg)