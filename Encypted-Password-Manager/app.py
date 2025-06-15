import tkinter as tk
from tkinter import messagebox
import os
import base64
import json
import sqlite3
import random
import string

# Ensure encryption_utils.py is in the same folder!
# It should contain the updated functions for the Vault Key architecture.
from encryption_utils import derive_key, encrypt_vault_key, decrypt_vault_key, encrypt_entry, decrypt_entry

class EncryptedPasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Password Manager")
        self.root.geometry("600x450")

        self.master_password_hash_file = "master_pass.json"
        self.master_password_data = self._load_master_password_data()

        self.vault_entries = []
        self.vault_key = None # Stores the decrypted Vault Key (VK) after successful login
        self._mp_derived_key_temp = None # Temporarily stores the Master Password Derived Key (MPDK) during login/change flows
        self.editing_entry_index = -1

        self._connect_db()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Initialize all screens (frames)
        self.login_screen()
        self.dashboard_screen()
        self.add_entry_screen()
        self.generate_password_screen()
        self.view_entries_screen()
        self.change_master_password_screen()

        self.show_screen("login")

    def _connect_db(self):
        """Connects to the SQLite database and creates the 'entries' table if it doesn't exist."""
        self.conn = sqlite3.connect('vault.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                salt TEXT NOT NULL,
                iv TEXT NOT NULL
            )
        ''')
        self.conn.commit()

    def _close_db(self):
        """Closes the SQLite database connection."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()

    def _load_master_password_data(self):
        """Loads master password hash, salt, and encrypted vault key from 'master_pass.json'."""
        if os.path.exists(self.master_password_hash_file):
            try:
                with open(self.master_password_hash_file, 'r') as f:
                    data = json.load(f)
                    data['hashed_password'] = base64.b64decode(data['hashed_password'])
                    data['salt'] = base64.b64decode(data['salt'])
                    data['encrypted_vault_key'] = base64.b64decode(data['encrypted_vault_key'])
                    data['vk_iv'] = base64.b64decode(data['vk_iv'])
                    return data
            except (json.JSONDecodeError, KeyError) as e:
                messagebox.showerror("Error", f"Master password file corrupted. Please delete 'master_pass.json' and restart. Error: {e}")
                return None
        return None

    def _save_master_password_data(self, hashed_password_bytes, salt_bytes, encrypted_vk_bytes, vk_iv_bytes):
        """Saves master password hash, salt, and encrypted vault key to 'master_pass.json'."""
        data = {
            'hashed_password': base64.b64encode(hashed_password_bytes).decode('utf-8'),
            'salt': base64.b64encode(salt_bytes).decode('utf-8'),
            'encrypted_vault_key': base64.b64encode(encrypted_vk_bytes).decode('utf-8'),
            'vk_iv': base64.b64encode(vk_iv_bytes).decode('utf-8')
        }
        with open(self.master_password_hash_file, 'w') as f:
            json.dump(data, f)
        self.master_password_data = {
            'hashed_password': hashed_password_bytes,
            'salt': salt_bytes,
            'encrypted_vault_key': encrypted_vk_bytes,
            'vk_iv': vk_iv_bytes
        }

    def _load_vault_entries_from_db(self):
        """Loads encrypted vault entries from the SQLite database into memory."""
        self.vault_entries = []
        if not self.vault_key: # Ensure vault key is available before attempting decryption
            return

        try:
            self.cursor.execute('SELECT id, site, username, ciphertext, salt, iv FROM entries')
            rows = self.cursor.fetchall()
            for row in rows:
                db_id, site, username, ciphertext, salt, iv = row
                self.vault_entries.append({
                    'id': db_id,
                    'site': site,
                    'username': username,
                    'password_enc': {
                        'ciphertext': ciphertext,
                        'salt': salt,
                        'iv': iv
                    }
                })
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to load entries from database: {e}")

    def on_closing(self):
        """Handles graceful shutdown when the window is closed."""
        self._close_db()
        self.root.destroy()

    def hide_all(self):
        """Hides all frames in the root window."""
        for widget in self.root.winfo_children():
            widget.pack_forget()

    def show_screen(self, screen_name):
        """Displays the specified screen and updates the UI."""
        self.hide_all()
        if screen_name == "login":
            self.login_frame.destroy()
            self.login_screen()
            self.login_frame.pack(fill="both", expand=1)
        elif screen_name == "dashboard":
            self.dashboard_frame.pack(fill="both", expand=1)
        elif screen_name == "add_entry":
            self.add_entry_frame.destroy()
            self.add_entry_screen()
            self.add_entry_frame.pack(fill="both", expand=1)
        elif screen_name == "generate_password":
            self.generate_password_frame.pack(fill="both", expand=1)
        elif screen_name == "view_entries":
            self.update_view_entries_list()
            self.view_entries_frame.pack(fill="both", expand=1)
        elif screen_name == "change_master_password":
            self.change_master_password_frame.destroy()
            self.change_master_password_screen()
            self.change_master_password_frame.pack(fill="both", expand=1)

        self.root.update_idletasks()
        self.root.update()

    # --- Login Screen ---
    def login_screen(self):
        """Sets up the login/master password creation screen."""
        self.login_frame = tk.Frame(self.root)
        tk.Label(self.login_frame, text="Master Password", font=("Arial", 16, "bold")).pack(pady=20)
        self.entry_password = tk.Entry(self.login_frame, show="*", width=40, font=("Arial", 12))
        self.entry_password.pack(pady=10)

        if self.master_password_data:
            tk.Label(self.login_frame, text="Enter your existing Master Password to login.", fg="gray").pack(pady=5)
            self.login_button = tk.Button(self.login_frame, text="Login", command=self.check_login, cursor='hand2', font=("Arial", 12))
            self.login_button.pack(pady=10)
        else:
            tk.Label(self.login_frame, text="No Master Password set. Please create one to get started.", fg="red", font=("Arial", 10)).pack(pady=5)
            self.set_master_password_button = tk.Button(self.login_frame, text="Set Master Password", command=self.set_master_password, cursor='hand2', font=("Arial", 12))
            self.set_master_password_button.pack(pady=10)

    def set_master_password(self):
        """Handles setting the master password for the first time."""
        master_pass = self.entry_password.get()
        if not master_pass:
            messagebox.showwarning("Warning", "Master Password cannot be empty.")
            return

        mp_salt = os.urandom(16)
        mp_derived_key = derive_key(master_pass, mp_salt)

        vault_key = os.urandom(32) # Generate a new 32-byte Vault Key (VK)
        encrypted_vk_data = encrypt_vault_key(vault_key, mp_derived_key)

        self._save_master_password_data(
            hashed_password_bytes=mp_derived_key,
            salt_bytes=mp_salt,
            encrypted_vk_bytes=base64.b64decode(encrypted_vk_data['ciphertext']),
            vk_iv_bytes=base64.b64decode(encrypted_vk_data['iv'])
        )
        self.vault_key = vault_key
        self._mp_derived_key_temp = mp_derived_key

        self.entry_password.delete(0, tk.END)
        self._load_vault_entries_from_db()
        self.show_screen("dashboard")

    def check_login(self):
        """Checks the entered master password against the stored hash."""
        entered_password = self.entry_password.get()
        if not entered_password:
            messagebox.showwarning("Warning", "Please enter your Master Password.")
            return

        if not self.master_password_data:
            messagebox.showerror("Error", "No master password found. Please set one.")
            return

        stored_mp_salt = self.master_password_data['salt']
        stored_hashed_password = self.master_password_data['hashed_password']
        stored_encrypted_vk = self.master_password_data['encrypted_vault_key']
        stored_vk_iv = self.master_password_data['vk_iv']

        entered_mp_derived_key = derive_key(entered_password, stored_mp_salt)

        if entered_mp_derived_key == stored_hashed_password:
            try:
                self.vault_key = decrypt_vault_key(
                    base64.b64encode(stored_encrypted_vk).decode('utf-8'),
                    base64.b64encode(stored_vk_iv).decode('utf-8'),
                    entered_mp_derived_key
                )
                self._mp_derived_key_temp = entered_mp_derived_key
                
                self._load_vault_entries_from_db()
                self.show_screen("dashboard")
                self.entry_password.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Decryption Error", f"Failed to decrypt vault key. Master Password file might be corrupted. Error: {e}")
                self.vault_key = None
                self._mp_derived_key_temp = None
        else:
            messagebox.showerror("Error", "Incorrect Master Password")
            self.vault_key = None
            self._mp_derived_key_temp = None

    # --- Dashboard Screen ---
    def dashboard_screen(self):
        """Sets up the main dashboard screen."""
        self.dashboard_frame = tk.Frame(self.root)
        tk.Label(self.dashboard_frame, text="Dashboard", font=("Arial", 16, "bold")).pack(pady=20)
        
        tk.Button(self.dashboard_frame, text="Add New Entry", width=30, command=lambda: self.show_screen("add_entry"), font=("Arial", 12)).pack(pady=10)
        
        tk.Button(self.dashboard_frame, text="Manage Entries", width=30, command=lambda: self.show_screen("view_entries"), font=("Arial", 12)).pack(pady=10)
        
        tk.Button(self.dashboard_frame, text="Generate Password", width=30, command=lambda: self.show_screen("generate_password"), font=("Arial", 12)).pack(pady=10)
        
        tk.Button(self.dashboard_frame, text="Change Master Password", width=30, command=lambda: self.show_screen("change_master_password"), font=("Arial", 12)).pack(pady=10)

        tk.Button(self.dashboard_frame, text="Logout", width=30, command=self.logout, font=("Arial", 12)).pack(pady=20)

    def logout(self):
        """Logs out the user, clearing the vault key and vault entries from memory."""
        self.vault_key = None
        self._mp_derived_key_temp = None
        self.vault_entries = []
        self.editing_entry_index = -1
        
        self.show_screen("login")

    # --- Add New Entry / Edit Entry Screen ---
    def add_entry_screen(self):
        """Sets up the screen for adding new or editing existing password entries."""
        self.add_entry_frame = tk.Frame(self.root)
        
        title_text = "Edit Entry" if self.editing_entry_index != -1 else "Add New Entry"
        tk.Label(self.add_entry_frame, text=title_text, font=("Arial", 16, "bold")).pack(pady=10)

        tk.Label(self.add_entry_frame, text="Site Name:", font=("Arial", 10)).pack(anchor="w", padx=10, pady=(10,0))
        self.site_entry = tk.Entry(self.add_entry_frame, width=40, font=("Arial", 10))
        self.site_entry.pack(pady=5)

        tk.Label(self.add_entry_frame, text="Username:", font=("Arial", 10)).pack(anchor="w", padx=10, pady=(5,0))
        self.username_entry = tk.Entry(self.add_entry_frame, width=40, font=("Arial", 10))
        self.username_entry.pack(pady=5)

        tk.Label(self.add_entry_frame, text="Password:", font=("Arial", 10)).pack(anchor="w", padx=10, pady=(5,0))
        self.password_entry = tk.Entry(self.add_entry_frame, width=40, show="*", font=("Arial", 10))
        self.password_entry.pack(pady=5)

        button_frame = tk.Frame(self.add_entry_frame)
        button_frame.pack(pady=10)
        tk.Button(button_frame, text="Generate Password", command=self.generate_password_for_add, font=("Arial", 10)).pack(side="left", padx=5)
        tk.Button(button_frame, text="Save Entry", command=self.save_entry, font=("Arial", 10)).pack(side="left", padx=5)

        tk.Button(self.add_entry_frame, text="Back to Dashboard", command=lambda: self.show_screen("dashboard"), font=("Arial", 10)).pack(pady=10)

        if self.editing_entry_index != -1:
            try:
                entry = self.vault_entries[self.editing_entry_index]
                self.site_entry.insert(0, entry['site'])
                self.username_entry.insert(0, entry['username'])
                
                decrypted_pass = decrypt_entry(
                    entry['password_enc']['ciphertext'],
                    self.vault_key,
                    entry['password_enc']['salt'],
                    entry['password_enc']['iv']
                )
                self.password_entry.insert(0, decrypted_pass)
            except Exception as e:
                messagebox.showerror("Error", f"Could not load entry for editing: {e}")
                self.editing_entry_index = -1

    def generate_password_for_add(self):
        """Generates a random password and inserts it into the password entry field."""
        length = 12
        chars = string.ascii_letters + string.digits + string.punctuation
        new_pass = ''.join(random.choices(chars, k=length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, new_pass)

    def save_entry(self):
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        plaintext_password = self.password_entry.get()

        if not site or not username or not plaintext_password:
            messagebox.showwarning("Warning", "Please fill all fields!")
            return
        if not self.vault_key:
            messagebox.showerror("Error", "Not logged in. Cannot save entry without a vault key.")
            return

        try:
            encrypted_data = encrypt_entry(plaintext_password, self.vault_key)

            if self.editing_entry_index != -1: # It's an edit operation
                original_entry = self.vault_entries[self.editing_entry_index]
                entry_id = original_entry['id']

                self.cursor.execute('''
                    UPDATE entries
                    SET site = ?, username = ?, ciphertext = ?, salt = ?, iv = ?
                    WHERE id = ?
                ''', (site, username, encrypted_data['ciphertext'],
                      encrypted_data['salt'], encrypted_data['iv'], entry_id))
                self.conn.commit()

                original_entry.update({
                    'site': site,
                    'username': username,
                    'password_enc': encrypted_data
                })
                messagebox.showinfo("Saved", f"Entry for '{site}' updated successfully!")

            else: # It's a new entry operation
                self.cursor.execute('''
                    INSERT INTO entries (site, username, ciphertext, salt, iv)
                    VALUES (?, ?, ?, ?, ?)
                ''', (site, username, encrypted_data['ciphertext'], encrypted_data['salt'], encrypted_data['iv']))
                self.conn.commit()
                
                new_id = self.cursor.lastrowid
                self.vault_entries.append({
                    'id': new_id,
                    'site': site,
                    'username': username,
                    'password_enc': encrypted_data
                })
                messagebox.showinfo("Saved", f"Entry for '{site}' saved successfully!")

            self.site_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.editing_entry_index = -1

            self.show_screen("view_entries")

        except Exception as e:
            messagebox.showerror("Encryption/Database Error", f"Failed to save entry: {e}")
            self.conn.rollback()

    # --- Password Generator Screen ---
    def generate_password_screen(self):
        self.generate_password_frame = tk.Frame(self.root)
        tk.Label(self.generate_password_frame, text="Generate a Strong Password", font=("Arial", 16, "bold")).pack(pady=20)
        self.generated_pass_entry = tk.Entry(self.generate_password_frame, width=50, font=("Arial", 12))
        self.generated_pass_entry.pack(pady=10)
        tk.Button(self.generate_password_frame, text="Generate Password", command=self.generate_password_only, font=("Arial", 12)).pack(pady=10)
        tk.Button(self.generate_password_frame, text="Copy to Clipboard", command=self.copy_generated_password, font=("Arial", 12)).pack(pady=5)
        tk.Button(self.generate_password_frame, text="Back to Dashboard", command=lambda: self.show_screen("dashboard"), font=("Arial", 12)).pack(pady=20)

    def generate_password_only(self):
        length = 16
        chars = string.ascii_letters + string.digits + string.punctuation
        new_pass = ''.join(random.choices(chars, k=length))
        self.generated_pass_entry.delete(0, tk.END)
        self.generated_pass_entry.insert(0, new_pass)

    def copy_generated_password(self):
        generated_pass = self.generated_pass_entry.get()
        if generated_pass:
            self.root.clipboard_clear()
            self.root.clipboard_append(generated_pass)
            messagebox.showinfo("Copied", "Generated password copied to clipboard. It will clear in 30 seconds.")
            self.root.after(30000, self.root.clipboard_clear)
        else:
            messagebox.showwarning("Warning", "No password generated to copy.")

    # --- View/Edit/Delete Entries Screen ---
    def view_entries_screen(self):
        self.view_entries_frame = tk.Frame(self.root)
        tk.Label(self.view_entries_frame, text="Your Saved Entries", font=("Arial", 16, "bold")).pack(pady=10)

        list_frame = tk.Frame(self.view_entries_frame)
        list_frame.pack(pady=10, fill="both", expand=True)

        self.entry_listbox = tk.Listbox(list_frame, width=70, height=10, font=("Arial", 10), bd=2, relief="groove")
        self.entry_listbox.pack(side="left", fill="both", expand=True, padx=5)

        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.entry_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.entry_listbox.config(yscrollcommand=scrollbar.set)

        self.entry_listbox.bind("<<ListboxSelect>>", self.on_entry_select)

        detail_frame = tk.Frame(self.view_entries_frame)
        detail_frame.pack(pady=10)

        tk.Label(detail_frame, text="Selected Entry Details:", font=("Arial", 12, "underline")).pack(pady=(5,0))
        self.detail_label = tk.Label(detail_frame, text="Select an entry to view details.", wraplength=550, justify="left", font=("Arial", 10))
        self.detail_label.pack(pady=5)

        action_buttons_frame = tk.Frame(self.view_entries_frame)
        action_buttons_frame.pack(pady=10)
        tk.Button(action_buttons_frame, text="Toggle Password Visibility", command=self.toggle_password_visibility, font=("Arial", 10)).pack(side="left", padx=5)
        tk.Button(action_buttons_frame, text="Copy Password", command=self.copy_password, font=("Arial", 10)).pack(side="left", padx=5)
        tk.Button(action_buttons_frame, text="Delete Selected", command=self.delete_selected_entry, font=("Arial", 10)).pack(side="left", padx=5)
        tk.Button(action_buttons_frame, text="Edit Selected", command=self.edit_selected_entry, font=("Arial", 10)).pack(side="left", padx=5)

        tk.Button(self.view_entries_frame, text="Back to Dashboard", command=lambda: self.show_screen("dashboard"), font=("Arial", 12)).pack(pady=20)

        self.current_selected_index = -1
        self.password_visible_for_index = -1

    def edit_selected_entry(self):
        """Prepares the add_entry_screen for editing the selected entry."""
        if self.current_selected_index == -1:
            messagebox.showwarning("Warning", "Please select an entry to edit.")
            return

        self.editing_entry_index = self.current_selected_index
        self.show_screen("add_entry")

    def update_view_entries_list(self):
        """Clears and repopulates the listbox with current vault entries."""
        self.entry_listbox.delete(0, tk.END)
        if not self.vault_entries:
            self.entry_listbox.insert(tk.END, "No entries saved yet. Add some from the Dashboard!")
            self.detail_label.config(text="Select an entry to view details.")
            self.current_selected_index = -1
            self.password_visible_for_index = -1
            return

        for i, entry in enumerate(self.vault_entries):
            display_text = f"{i+1}. Site: {entry['site']} | Username: {entry['username']}"
            self.entry_listbox.insert(tk.END, display_text)

        self.detail_label.config(text="Select an entry to view details.")
        self.current_selected_index = -1
        self.password_visible_for_index = -1

    def on_entry_select(self, event):
        """Event handler for when an item in the listbox is selected."""
        selected_indices = self.entry_listbox.curselection()
        if not selected_indices:
            self.current_selected_index = -1
            self.detail_label.config(text="Select an entry to view details.")
            self.password_visible_for_index = -1
            return

        self.current_selected_index = selected_indices[0]
        self.password_visible_for_index = -1
        self.editing_entry_index = -1
        self.display_entry_details(self.current_selected_index)

    def display_entry_details(self, index):
        """Updates the detail label with information about the selected entry."""
        if 0 <= index < len(self.vault_entries):
            entry = self.vault_entries[index]
            password_display = "********"
            if self.password_visible_for_index == index:
                try:
                    decrypted_pass = decrypt_entry(
                        entry['password_enc']['ciphertext'],
                        self.vault_key,
                        entry['password_enc']['salt'],
                        entry['password_enc']['iv']
                    )
                    password_display = decrypted_pass
                except Exception as e:
                    password_display = f"Decryption Error: {e}"

            details_text = (
                f"Site: {entry['site']}\n"
                f"Username: {entry['username']}\n"
                f"Password: {password_display}"
            )
            self.detail_label.config(text=details_text)
        else:
            self.detail_label.config(text="Invalid entry selected.")

    def toggle_password_visibility(self):
        """Toggles the visibility of the password for the selected entry."""
        if self.current_selected_index == -1:
            messagebox.showwarning("Warning", "Please select an entry first.")
            return

        if not self.vault_key:
            messagebox.showerror("Error", "Not logged in. Cannot decrypt password.")
            return

        if self.password_visible_for_index == self.current_selected_index:
            self.password_visible_for_index = -1
        else:
            self.password_visible_for_index = self.current_selected_index

        self.display_entry_details(self.current_selected_index)

    def copy_password(self):
        """Copies the decrypted password of the selected entry to the clipboard."""
        if self.current_selected_index == -1:
            messagebox.showwarning("Warning", "Please select an entry first.")
            return

        if not self.vault_key:
            messagebox.showerror("Error", "Not logged in. Cannot copy password.")
            return

        try:
            entry = self.vault_entries[self.current_selected_index]
            decrypted_pass = decrypt_entry(
                entry['password_enc']['ciphertext'],
                self.vault_key,
                entry['password_enc']['salt'],
                entry['password_enc']['iv']
            )
            self.root.clipboard_clear()
            self.root.clipboard_append(decrypted_pass)
            messagebox.showinfo("Copied", "Password copied to clipboard. It will clear in 30 seconds.")
            self.root.after(30000, self.root.clipboard_clear)
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy password: {e}")

    def delete_selected_entry(self):
        """Deletes the selected entry from the SQLite database and in-memory list."""
        if self.current_selected_index == -1:
            messagebox.showwarning("Warning", "Please select an entry to delete.")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            entry_to_delete = self.vault_entries[self.current_selected_index]
            entry_id_to_delete = entry_to_delete['id']

            try:
                self.cursor.execute('DELETE FROM entries WHERE id = ?', (entry_id_to_delete,))
                self.conn.commit()

                del self.vault_entries[self.current_selected_index]
                messagebox.showinfo("Deleted", "Entry deleted successfully.")
                self.update_view_entries_list()
                self.detail_label.config(text="Select an entry to view details.")
                self.current_selected_index = -1
                self.password_visible_for_index = -1
            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"Failed to delete entry from database: {e}")
                self.conn.rollback()

    # --- Change Master Password Screen and Logic (Now safe for data!) ---
    def change_master_password_screen(self):
        self.change_master_password_frame = tk.Frame(self.root)
        tk.Label(self.change_master_password_frame, text="Change Master Password", font=("Arial", 16, "bold")).pack(pady=20)

        tk.Label(self.change_master_password_frame, text="Current Master Password:", font=("Arial", 10)).pack(anchor="w", padx=10, pady=(5,0))
        self.current_master_pass_entry = tk.Entry(self.change_master_password_frame, show="*", width=40, font=("Arial", 10))
        self.current_master_pass_entry.pack(pady=5)

        tk.Label(self.change_master_password_frame, text="New Master Password:", font=("Arial", 10)).pack(anchor="w", padx=10, pady=(5,0))
        self.new_master_pass_entry = tk.Entry(self.change_master_password_frame, show="*", width=40, font=("Arial", 10))
        self.new_master_pass_entry.pack(pady=5)

        tk.Label(self.change_master_password_frame, text="Confirm New Master Password:", font=("Arial", 10)).pack(anchor="w", padx=10, pady=(5,0))
        self.confirm_new_master_pass_entry = tk.Entry(self.change_master_password_frame, show="*", width=40, font=("Arial", 10))
        self.confirm_new_master_pass_entry.pack(pady=5)

        tk.Button(self.change_master_password_frame, text="Change Password", command=self.perform_change_master_password, font=("Arial", 12)).pack(pady=15)
        tk.Button(self.change_master_password_frame, text="Back to Dashboard", command=lambda: self.show_screen("dashboard"), font=("Arial", 12)).pack(pady=10)

    def perform_change_master_password(self):
        current_pass = self.current_master_pass_entry.get()
        new_pass = self.new_master_pass_entry.get()
        confirm_new_pass = self.confirm_new_master_pass_entry.get()

        if not current_pass or not new_pass or not confirm_new_pass:
            messagebox.showwarning("Warning", "All fields must be filled.")
            return

        if not self.master_password_data:
            messagebox.showerror("Error", "No master password set. Cannot change.")
            self.show_screen("login")
            return
        
        # Verify current master password (MPDK)
        stored_mp_salt = self.master_password_data['salt']
        stored_hashed_password = self.master_password_data['hashed_password']
        entered_mp_derived_key = derive_key(current_pass, stored_mp_salt)

        if entered_mp_derived_key != stored_hashed_password:
            messagebox.showerror("Error", "Incorrect Current Master Password.")
            return

        # Validate new master password
        if new_pass != confirm_new_pass:
            messagebox.showwarning("Warning", "New passwords do not match.")
            return
        if new_pass == current_pass:
            messagebox.showwarning("Warning", "New password cannot be the same as the current password.")
            return
        if len(new_pass) < 8:
            messagebox.showwarning("Warning", "New password should be at least 8 characters long.")
            return

        try:
            # Step 1: Decrypt the existing Vault Key (VK) using the old MPDK
            stored_encrypted_vk = self.master_password_data['encrypted_vault_key']
            stored_vk_iv = self.master_password_data['vk_iv']
            
            current_vault_key = decrypt_vault_key(
                base64.b64encode(stored_encrypted_vk).decode('utf-8'),
                base64.b64encode(stored_vk_iv).decode('utf-8'),
                entered_mp_derived_key # Use the verified old MPDK to decrypt VK
            )

            # Step 2: Derive a NEW Master Password Derived Key (New MPDK) from the new password
            new_mp_salt = os.urandom(16)
            new_mp_derived_key = derive_key(new_pass, new_mp_salt)

            # Step 3: Encrypt the SAME Vault Key (VK) with the New MPDK
            new_encrypted_vk_data = encrypt_vault_key(current_vault_key, new_mp_derived_key)

            # Step 4: Save the new Master Password hash, new salt, and the newly encrypted Vault Key
            self._save_master_password_data(
                hashed_password_bytes=new_mp_derived_key,
                salt_bytes=new_mp_salt,
                encrypted_vk_bytes=base64.b64decode(new_encrypted_vk_data['ciphertext']),
                vk_iv_bytes=base64.b64decode(new_encrypted_vk_data['iv'])
            )
            
            self.vault_key = current_vault_key
            self._mp_derived_key_temp = new_mp_derived_key

            messagebox.showinfo("Success", "Master Password changed successfully! Your vault entries are secure.")
            
            self.current_master_pass_entry.delete(0, tk.END)
            self.new_master_pass_entry.delete(0, tk.END)
            self.confirm_new_master_pass_entry.delete(0, tk.END)
            self.show_screen("dashboard")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while changing master password: {e}\nYour master password may not have been changed.")


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptedPasswordManagerApp(root)
    root.mainloop()