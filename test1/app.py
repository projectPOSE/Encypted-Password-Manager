import tkinter as tk
from tkinter import messagebox
import os
import base64
import json
import sqlite3
import random
import string

from encryption_utils import derive_key, encrypt, decrypt # Ensure encryption_utils.py is in the same folder!

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Password Manager")
        self.root.geometry("600x450") # Increased size for better layout

        self.master_password_hash_file = "master_pass.json"
        self.master_password_data = self._load_master_password_data()

        self.vault_entries = []
        self.current_master_key = None # Stores the derived key after successful login

        self._connect_db()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing) # Handles graceful shutdown

        # Initialize all screens (frames)
        self.login_screen()
        self.dashboard_screen()
        self.add_entry_screen()
        self.generate_password_screen()
        self.view_entries_screen()

        self.show_screen("login") # Show login screen at start

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
        """Loads master password hash and salt from 'master_pass.json' for persistence."""
        if os.path.exists(self.master_password_hash_file):
            try:
                with open(self.master_password_hash_file, 'r') as f:
                    data = json.load(f)
                    data['hashed_password'] = base64.b64decode(data['hashed_password'])
                    data['salt'] = base64.b64decode(data['salt'])
                    return data
            except (json.JSONDecodeError, KeyError) as e:
                messagebox.showerror("Error", f"Master password file corrupted. Please delete 'master_pass.json' and restart. Error: {e}")
                return None
        return None

    def _save_master_password_data(self, hashed_password_bytes, salt_bytes):
        """Saves master password hash and salt to 'master_pass.json'."""
        data = {
            'hashed_password': base64.b64encode(hashed_password_bytes).decode('utf-8'),
            'salt': base64.b64encode(salt_bytes).decode('utf-8')
        }
        with open(self.master_password_hash_file, 'w') as f:
            json.dump(data, f)
        self.master_password_data = data # Update in-memory copy

    def _load_vault_entries_from_db(self):
        """Loads encrypted vault entries from the SQLite database into memory."""
        self.vault_entries = [] # Clear current in-memory list
        try:
            self.cursor.execute('SELECT site, username, ciphertext, salt, iv FROM entries')
            rows = self.cursor.fetchall()
            for row in rows:
                site, username, ciphertext, salt, iv = row
                self.vault_entries.append({
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
            self.login_frame.destroy() # Destroy previous frame
            self.login_screen() # Re-create with current state
            self.login_frame.pack(fill="both", expand=1)
        elif screen_name == "dashboard":
            self.dashboard_frame.pack(fill="both", expand=1)
        elif screen_name == "add_entry":
            self.add_entry_frame.pack(fill="both", expand=1)
        elif screen_name == "generate_password":
            self.generate_password_frame.pack(fill="both", expand=1)
        elif screen_name == "view_entries":
            self.update_view_entries_list()
            self.view_entries_frame.pack(fill="both", expand=1)

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

        salt = os.urandom(16)
        derived_key_bytes = derive_key(master_pass, salt)

        self._save_master_password_data(derived_key_bytes, salt)
        self.current_master_key = derived_key_bytes

        messagebox.showinfo("Success", "Master Password set successfully! You are now logged in.")
        self.entry_password.delete(0, tk.END)
        self._load_vault_entries_from_db() # Load entries after setting master password
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

        stored_salt = self.master_password_data['salt']
        stored_hashed_password = self.master_password_data['hashed_password']

        derived_key_for_check = derive_key(entered_password, stored_salt)

        if derived_key_for_check == stored_hashed_password:
            self.current_master_key = derived_key_for_check
            messagebox.showinfo("Success", "Login successful!")
            self._load_vault_entries_from_db() # Load entries after successful login
            self.show_screen("dashboard")
            self.entry_password.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Incorrect Master Password")

    # --- Dashboard Screen ---
    def dashboard_screen(self):
        """Sets up the main dashboard screen."""
        self.dashboard_frame = tk.Frame(self.root)
        tk.Label(self.dashboard_frame, text="Dashboard", font=("Arial", 16, "bold")).pack(pady=20)
        tk.Button(self.dashboard_frame, text="View/Edit/Delete Entries", width=30, command=lambda: self.show_screen("view_entries"), font=("Arial", 12)).pack(pady=10)
        tk.Button(self.dashboard_frame, text="Add New Entry", width=30, command=lambda: self.show_screen("add_entry"), font=("Arial", 12)).pack(pady=10)
        tk.Button(self.dashboard_frame, text="Generate Password", width=30, command=lambda: self.show_screen("generate_password"), font=("Arial", 12)).pack(pady=10)
        tk.Button(self.dashboard_frame, text="Logout", width=30, command=self.logout, font=("Arial", 12)).pack(pady=20)

    def logout(self):
        """Logs out the user, clearing the master key from memory."""
        self.current_master_key = None
        self.vault_entries = [] # Clear entries from memory
        messagebox.showinfo("Logout", "Logged out successfully.")
        self.show_screen("login")

    # --- Add New Entry Screen ---
    def add_entry_screen(self):
        """Sets up the screen for adding new password entries."""
        self.add_entry_frame = tk.Frame(self.root)
        tk.Label(self.add_entry_frame, text="Add New Entry", font=("Arial", 16, "bold")).pack(pady=10)

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

    def generate_password_for_add(self):
        """Generates a random password and inserts it into the password entry field."""
        length = 12
        chars = string.ascii_letters + string.digits + string.punctuation
        new_pass = ''.join(random.choices(chars, k=length))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, new_pass)

    def save_entry(self):
        """Encrypts and saves a new password entry to the SQLite database and in-memory storage."""
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        plaintext_password = self.password_entry.get()

        if not site or not username or not plaintext_password:
            messagebox.showwarning("Warning", "Please fill all fields!")
            return
        if not self.current_master_key:
            messagebox.showerror("Error", "Not logged in. Cannot save entry without a master key.")
            return

        try:
            encrypted_data = encrypt(plaintext_password, self.current_master_key.decode('latin-1'))

            self.cursor.execute('''
                INSERT INTO entries (site, username, ciphertext, salt, iv)
                VALUES (?, ?, ?, ?, ?)
            ''', (site, username, encrypted_data['ciphertext'], encrypted_data['salt'], encrypted_data['iv']))
            self.conn.commit()

            # Append to in-memory list AFTER successful database save
            self.vault_entries.append({
                'site': site,
                'username': username,
                'password_enc': encrypted_data
            })

            messagebox.showinfo("Saved", f"Entry for '{site}' saved successfully!")
            # Clear input fields
            self.site_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Encryption/Database Error", f"Failed to save entry: {e}")
            self.conn.rollback()

    # --- Password Generator Screen ---
    def generate_password_screen(self):
        """Sets up the standalone password generator screen."""
        self.generate_password_frame = tk.Frame(self.root)
        tk.Label(self.generate_password_frame, text="Generate a Strong Password", font=("Arial", 16, "bold")).pack(pady=20)
        self.generated_pass_entry = tk.Entry(self.generate_password_frame, width=50, font=("Arial", 12))
        self.generated_pass_entry.pack(pady=10)
        tk.Button(self.generate_password_frame, text="Generate Password", command=self.generate_password_only, font=("Arial", 12)).pack(pady=10)
        tk.Button(self.generate_password_frame, text="Copy to Clipboard", command=self.copy_generated_password, font=("Arial", 12)).pack(pady=5)
        tk.Button(self.generate_password_frame, text="Back to Dashboard", command=lambda: self.show_screen("dashboard"), font=("Arial", 12)).pack(pady=20)

    def generate_password_only(self):
        """Generates a random password for the dedicated generator screen."""
        length = 16
        chars = string.ascii_letters + string.digits + string.punctuation
        new_pass = ''.join(random.choices(chars, k=length))
        self.generated_pass_entry.delete(0, tk.END)
        self.generated_pass_entry.insert(0, new_pass)

    def copy_generated_password(self):
        """Copies the generated password to the clipboard and sets auto-clear."""
        generated_pass = self.generated_pass_entry.get()
        if generated_pass:
            self.root.clipboard_clear()
            self.root.clipboard_append(generated_pass)
            messagebox.showinfo("Copied", "Generated password copied to clipboard. It will clear in 30 seconds.")
            self.root.after(30000, self.root.clipboard_clear) # Schedule clipboard to clear after 30 seconds
        else:
            messagebox.showwarning("Warning", "No password generated to copy.")

    # --- View/Edit/Delete Entries Screen ---
    def view_entries_screen(self):
        """Sets up the screen for viewing and managing saved password entries."""
        self.view_entries_frame = tk.Frame(self.root)
        tk.Label(self.view_entries_frame, text="Your Saved Entries", font=("Arial", 16, "bold")).pack(pady=10)

        list_frame = tk.Frame(self.view_entries_frame)
        list_frame.pack(pady=10, fill="both", expand=True)

        self.entry_listbox = tk.Listbox(list_frame, width=70, height=10, font=("Arial", 10), bd=2, relief="groove")
        self.entry_listbox.pack(side="left", fill="both", expand=True, padx=5)

        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.entry_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.entry_listbox.config(yscrollcommand=scrollbar.set)

        self.entry_listbox.bind("<<ListboxSelect>>", self.on_entry_select) # Bind selection event

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

        tk.Button(self.view_entries_frame, text="Back to Dashboard", command=lambda: self.show_screen("dashboard"), font=("Arial", 12)).pack(pady=20)

        self.current_selected_index = -1
        self.password_visible_for_index = -1 # Track which password is currently visible

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
        self.password_visible_for_index = -1 # Reset visibility when a new entry is selected
        self.display_entry_details(self.current_selected_index)

    def display_entry_details(self, index):
        """Updates the detail label with information about the selected entry."""
        if 0 <= index < len(self.vault_entries):
            entry = self.vault_entries[index]
            password_display = "********" # Default hidden
            if self.password_visible_for_index == index:
                try:
                    decrypted_pass = decrypt(
                        entry['password_enc']['ciphertext'],
                        self.current_master_key.decode('latin-1'),
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

        if not self.current_master_key:
            messagebox.showerror("Error", "Not logged in. Cannot decrypt password.")
            return

        if self.password_visible_for_index == self.current_selected_index:
            self.password_visible_for_index = -1 # Hide it
        else:
            self.password_visible_for_index = self.current_selected_index # Show it

        self.display_entry_details(self.current_selected_index) # Refresh display to show change

    def copy_password(self):
        """Copies the decrypted password of the selected entry to the clipboard."""
        if self.current_selected_index == -1:
            messagebox.showwarning("Warning", "Please select an entry first.")
            return

        if not self.current_master_key:
            messagebox.showerror("Error", "Not logged in. Cannot copy password.")
            return

        try:
            entry = self.vault_entries[self.current_selected_index]
            decrypted_pass = decrypt(
                entry['password_enc']['ciphertext'],
                self.current_master_key.decode('latin-1'),
                entry['password_enc']['salt'],
                entry['password_enc']['iv']
            )
            self.root.clipboard_clear()
            self.root.clipboard_append(decrypted_pass)
            messagebox.showinfo("Copied", "Password copied to clipboard. It will clear in 30 seconds.")
            self.root.after(30000, self.root.clipboard_clear) # Schedule clipboard to clear after 30 seconds
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy password: {e}")

    def delete_selected_entry(self):
        """Deletes the selected entry from the SQLite database and in-memory list."""
        if self.current_selected_index == -1:
            messagebox.showwarning("Warning", "Please select an entry to delete.")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            entry_to_delete = self.vault_entries[self.current_selected_index]
            site_to_delete = entry_to_delete['site']
            username_to_delete = entry_to_delete['username']
            ciphertext_to_delete = entry_to_delete['password_enc']['ciphertext']

            try:
                self.cursor.execute('''
                    DELETE FROM entries
                    WHERE site = ? AND username = ? AND ciphertext = ?
                ''', (site_to_delete, username_to_delete, ciphertext_to_delete))
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


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()