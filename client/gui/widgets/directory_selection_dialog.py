import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os


class DirectorySelectionDialog:
    def __init__(self, parent):
        self.parent = parent
        self.selected_paths = []
        self.dialog = None
        self.create_dialog()


    def create_dialog(self):
        self.dialog = ctk.CTkToplevel(self.parent)
        self.dialog.title("Select Directories to Scan")
        self.dialog.geometry("600x500")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()


        title = ctk.CTkLabel(self.dialog, text="Select Directories to Scan", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=20)


        main_frame = ctk.CTkFrame(self.dialog)
        main_frame.pack(fill='both', expand=True, padx=20, pady=(0,20))


        browse_frame = ctk.CTkFrame(main_frame)
        browse_frame.pack(fill='x', padx=20, pady=10)


        ctk.CTkButton(browse_frame, text="Add Directory", command=self.browse_directory).pack(side='left', padx=5)
        ctk.CTkButton(browse_frame, text="Add Common Locations", command=self.add_common_locations).pack(side='right', padx=5)


        self.scroll_frame = ctk.CTkScrollableFrame(main_frame, height=300)
        self.scroll_frame.pack(fill='both', expand=True, padx=20, pady=(0,20))


        self.directory_vars = {}


        buttons_frame = ctk.CTkFrame(main_frame)
        buttons_frame.pack(fill='x', padx=20, pady=(0,20))


        ctk.CTkButton(buttons_frame, text="Select All", command=self.select_all).pack(side='left')
        ctk.CTkButton(buttons_frame, text="Clear All", command=self.clear_all).pack(side='left', padx=5)
        ctk.CTkButton(buttons_frame, text="Start Scan", command=self.confirm_selection, fg_color="#10b981").pack(side='right')
        ctk.CTkButton(buttons_frame, text="Cancel", command=self.cancel_selection, fg_color="#ef4444").pack(side='right', padx=5)


        self.add_common_locations()


    def browse_directory(self):
        directory = filedialog.askdirectory(title="Select directory to scan", initialdir=os.path.expanduser("~"))
        if directory:
            self.add_directory(directory)


    def add_directory(self, directory):
        if directory in self.directory_vars:
            return
        var = ctk.BooleanVar(value=True)
        self.directory_vars[directory] = var
        dir_frame = ctk.CTkFrame(self.scroll_frame)
        dir_frame.pack(fill='x', pady=2, padx=5)
        checkbox = ctk.CTkCheckBox(dir_frame, text=directory, variable=var)
        checkbox.pack(side='left', padx=10, pady=8)


    def add_common_locations(self):
        common_dirs = [os.path.expanduser('~/Desktop'), os.path.expanduser('~/Downloads'), os.path.expanduser('~/Documents'), os.path.expanduser('~/Pictures'), os.environ.get('TEMP', '/tmp')]
        for d in common_dirs:
            if os.path.exists(d):
                self.add_directory(d)


    def select_all(self):
        for v in self.directory_vars.values():
            v.set(True)


    def clear_all(self):
        for v in self.directory_vars.values():
            v.set(False)

        def confirm_selection(self):
            self.selected_paths = [p for p, v in self.directory_vars.items() if v.get()]

        if not self.selected_paths:
            messagebox.showwarning('No Selection', 'Please select at least one directory to scan.')
            return
        self.dialog.destroy()

    def cancel_selection(self):
        self.selected_paths = []
        self.dialog.destroy()

    def show(self):
        self.dialog.wait_window()
        return self.selected_paths