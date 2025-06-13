import tkinter as tk
from tkinter import messagebox
import os
import base64 # Needed for encoding/decoding salt/iv for storage
import json # For simple storage of master password hash and entries
import sqlite3
import random # For password generation
import string # For password generation
import time # For clipboard auto-clear

from encryption_utils import derive_key, encrypt, decrypt

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted Password Manager")
        self.root.geometry("600x450") # Increased size for better layout

        # --- IMPORTANT: Master Password Storage (for demo purposes) ---
        # In a real app, this would be in a secure file, not hardcoded.
        # For a demo, we'll simulate a saved master password hash.
        self.master_password_hash_file = "master_pass.json"
        self.master_password_data = self._load_master_password_data()
        # Debug print: Check if master password data was loaded
        print(f"DEBUG: master_password_data after load: {self.master_password_data}")

        # Temporary in-memory storage for vault entries (for demo)
        # In a real app, this would be encrypted and stored in SQLite.
        # Stores {'site': '', 'username': '', 'password_enc': {'ciphertext': '', 'salt': '', 'iv': ''}}
        self.vault_entries = []
        self.current_master_key = None # Will store the derived key after successful login
        self._connect_db()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize all screens in the same window but hidden
        self.login_screen()
        self.dashboard_screen()
        self.add_entry_screen()
        self.generate_password_screen()
        self.view_entries_screen() # New screen for viewing/managing entries

        # Show login screen at start
        self.show_screen("login")

    def _connect_db(self):
        """Connects to the SQLite database and creates the entries table if it doesn't exist."""
        self.conn = sqlite3.connect('vault.db')  # Connect to or create vault.db
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
        print("DEBUG: Database connected and table 'entries' ensured.")

    def _close_db(self):
        """Closes the database connection."""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()
            print("DEBUG: Database connection closed.")

    def _load_master_password_data(self):
        """
        Loads master password hash and salt from a file for persistence.
        For demo purposes only. In a real app, this would be more robust.
        """
        file_path = self.master_password_hash_file
        # Debug print: Check where the app is looking for the file
        print(f"DEBUG: Checking for master_pass file at: {os.path.abspath(file_path)}")

        if os.path.exists(self.master_password_hash_file):
            # Debug print: Confirm file found
            print("DEBUG: master_pass.json found.")
            try:
                with open(self.master_password_hash_file, 'r') as f:
                    data = json.load(f)
                    # Decode base64 strings back to bytes for use
                    data['hashed_password'] = base64.b64decode(data['hashed_password'])
                    data['salt'] = base64.b64decode(data['salt'])
                    # Debug print: Confirm file loaded successfully
                    print("DEBUG: master_pass.json loaded successfully.")
                    return data
            except json.JSONDecodeError as e:
                # Handle corrupted JSON file
                print(f"ERROR: Failed to decode master_pass.json: {e}")
                messagebox.showerror("Error", f"Master password file corrupted. Please delete 'master_pass.json' and restart.")
                return None
        # Debug print: Confirm file not found
        print("DEBUG: master_pass.json not found.")
        return None # No master password set yet

    def _save_master_password_data(self, hashed_password_bytes, salt_bytes):
        """
        Saves master password hash and salt to a file.
        For demo purposes only.
        """
        # Encode bytes to base64 strings for JSON serialization
        data = {
            'hashed_password': base64.b64encode(hashed_password_bytes).decode('utf-8'),
            'salt': base64.b64encode(salt_bytes).decode('utf-8')
        }
        with open(self.master_password_hash_file, 'w') as f:
            json.dump(data, f)
        self.master_password_data = data # Update in-memory copy

    def _load_vault_entries_from_db(self):
        """Loads encrypted vault entries from the database into memory."""
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
            print(f"DEBUG: Loaded {len(self.vault_entries)} entries from database.")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to load entries from database: {e}")
            print(f"ERROR: Database load error: {e}")

    def on_closing(self):
        """Handles graceful shutdown when the window is closed."""
        print("DEBUG: Application closing. Attempting to close database connection.")
        self._close_db() # Call the method to close the DB connection
        self.root.destroy() # Destroy the Tkinter root window

    def hide_all(self):
        """Hides all frames in the root window."""
        for widget in self.root.winfo_children():
            widget.pack_forget()

    def show_screen(self, screen_name):
        """Displays the specified screen."""
        self.hide_all()
        if screen_name == "login":
            # Re-create login screen to update buttons based on master_password_data state
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

        # Conditional button based on whether master password is set
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

        # Generate a new random salt
        salt = os.urandom(16)
        # Derive the key (hash) from the master password and salt using PBKDF2
        # This derived key is what we store and compare against for authentication
        # It also serves as the base key for encrypting/decrypting vault entries
        derived_key_bytes = derive_key(master_pass, salt)

        # Store the hashed password and salt for future logins
        self._save_master_password_data(derived_key_bytes, salt)
        self.current_master_key = derived_key_bytes # Store for current session's encryption/decryption

        messagebox.showinfo("Success", "Master Password set successfully! You are now logged in.")
        self.entry_password.delete(0, tk.END) # Clear password field
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

        # Retrieve stored salt and hashed password (in bytes)
        stored_salt = self.master_password_data['salt']
        stored_hashed_password = self.master_password_data['hashed_password']

        # Derive key from entered password and stored salt for comparison
        derived_key_for_check = derive_key(entered_password, stored_salt)

        if derived_key_for_check == stored_hashed_password:
            self.current_master_key = derived_key_for_check # Store for current session's encryption/decryption
            messagebox.showinfo("Success", "Login successful!")
            self._load_vault_entries_from_db()
            self.show_screen("dashboard")
            self.entry_password.delete(0, tk.END) # Clear password field
        else:
            messagebox.showerror("Error", "Incorrect Master Password")

    # --- Dashboard Screen (UI02) ---
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
        self.current_master_key = None # Clear the key from memory for security
        self.vault_entries = [] # Clear entries from memory (they'd be reloaded from DB after login in a real app)
        messagebox.showinfo("Logout", "Logged out successfully.")
        # Re-initialize login screen to show correct button state
        self.login_frame.destroy() # Destroy old login frame
        self.login_screen() # Create a fresh login frame
        self.show_screen("login") # Show the fresh login screen

    # --- Add New Entry Screen (UI04) ---
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
        self.password_entry = tk.Entry(self.add_entry_frame, width=40, show="*", font=("Arial", 10)) # Hide password by default
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
        """Encrypts and saves a new password entry to in-memory storage AND to the SQLite database."""
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        plaintext_password = self.password_entry.get() # This is the plaintext password

        if not site or not username or not plaintext_password:
            messagebox.showwarning("Warning", "Please fill all fields!")
            return
        if not self.current_master_key:
            messagebox.showerror("Error", "Not logged in. Cannot save entry without a master key.")
            return

        try:
            # ENCRYPT THE PLAINTEXT PASSWORD BEFORE STORING
            encrypted_data = encrypt(plaintext_password, self.current_master_key.decode('latin-1')) # Using latin-1 for byte->str conversion

            # --- CRITICAL FIX START ---
            # 1. Correct SQL INSERT statement
            # 2. Correct parameter passing using '?' placeholders
            # 3. Move self.conn.commit() here
            self.cursor.execute('''
                INSERT INTO entries (site, username, ciphertext, salt, iv)
                VALUES (?, ?, ?, ?, ?)
            ''', (site, username, encrypted_data['ciphertext'], encrypted_data['salt'], encrypted_data['iv']))
            self.conn.commit() # <--- COMMIT HERE after successful insert
            print(f"DEBUG: Entry for '{site}' saved to database.") # Confirm in terminal

            # 4. Append to in-memory list AFTER successful database save
            self.vault_entries.append({
                'site': site,
                'username': username,
                'password_enc': encrypted_data # Store the encrypted parts as a dictionary
            })
            # --- CRITICAL FIX END ---

            messagebox.showinfo("Saved", f"Entry for '{site}' saved successfully!")
            # Clear input fields
            self.site_entry.delete(0, tk.END)
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

        except Exception as e:
            messagebox.showerror("Encryption/Database Error", f"Failed to save entry: {e}")
            print(f"ERROR: Save entry error details: {e}")
            self.conn.rollback() # <--- ROLLBACK HERE if an error occurs during the transaction

    # --- Password Generator Screen (UI05) ---
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
            self.root.after(30000, self.root.clipboard_clear) # Auto-clear after 30s
        else:
            messagebox.showwarning("Warning", "No password generated to copy.")

    # --- NEW: View/Edit/Delete Entries Screen ---
    def view_entries_screen(self):
        """Sets up the screen for viewing and managing saved password entries."""
        self.view_entries_frame = tk.Frame(self.root)
        tk.Label(self.view_entries_frame, text="Your Saved Entries", font=("Arial", 16, "bold")).pack(pady=10)

        # Frame for listbox and scrollbar
        list_frame = tk.Frame(self.view_entries_frame)
        list_frame.pack(pady=10, fill="both", expand=True)

        self.entry_listbox = tk.Listbox(list_frame, width=70, height=10, font=("Arial", 10), bd=2, relief="groove")
        self.entry_listbox.pack(side="left", fill="both", expand=True, padx=5)

        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.entry_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.entry_listbox.config(yscrollcommand=scrollbar.set)

        self.entry_listbox.bind("<<ListboxSelect>>", self.on_entry_select) # Bind selection event

        # Detail view / Action buttons
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
            if self.password_visible_for_index == index: # If this specific entry's password is toggled visible
                try:
                    # DECRYPT THE PASSWORD FOR DISPLAY
                    # The decrypt function needs the master key as a string (decoded from bytes)
                    decrypted_pass = decrypt(
                        entry['password_enc']['ciphertext'],
                        self.current_master_key.decode('latin-1'), # Using latin-1 for byte->str conversion
                        entry['password_enc']['salt'],
                        entry['password_enc']['iv']
                    )
                    password_display = decrypted_pass
                except Exception as e:
                    password_display = f"Decryption Error: {e}" # Show error if decryption fails
            
            details_text = (
                f"Site: {entry['site']}\n"
                f"Username: {entry['username']}\n"
                f"Password: {password_display}" # Displays hidden or decrypted password
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

        # Toggle the visibility state for the selected entry
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
            # Decrypt the password before copying to clipboard
            decrypted_pass = decrypt(
                entry['password_enc']['ciphertext'],
                self.current_master_key.decode('latin-1'), # Using latin-1 for byte->str conversion
                entry['password_enc']['salt'],
                entry['password_enc']['iv']
            )
            self.root.clipboard_clear() # Clear existing clipboard content
            self.root.clipboard_append(decrypted_pass) # Add decrypted password
            messagebox.showinfo("Copied", "Password copied to clipboard. It will clear in 30 seconds.")
            self.root.after(30000, self.root.clipboard_clear) # Schedule clipboard to clear after 30 seconds
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy password: {e}")

    def delete_selected_entry(self):
        if self.current_selected_index == -1:
            messagebox.showwarning("Warning", "Please select an entry to delete.")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            entry_to_delete = self.vault_entries[self.current_selected_index]
            site_to_delete = entry_to_delete['site']
            username_to_delete = entry_to_delete['username']
            # We can also use ciphertext for a more robust WHERE clause if needed,
            # but site and username are usually unique enough for this demo.
            ciphertext_to_delete = entry_to_delete['password_enc']['ciphertext'] # Added for robustness

            try:
                # --- ADD THIS DATABASE DELETE OPERATION ---
                self.cursor.execute('''
                    DELETE FROM entries
                    WHERE site = ? AND username = ? AND ciphertext = ?
                ''', (site_to_delete, username_to_delete, ciphertext_to_delete))
                self.conn.commit() # <--- COMMIT THE DELETION TO THE DATABASE FILE
                print(f"DEBUG: Entry for '{site_to_delete}' deleted from database.") # Check your terminal

                # Only delete from in-memory list if database deletion was successful
                del self.vault_entries[self.current_selected_index]
                messagebox.showinfo("Deleted", "Entry deleted successfully.")
                self.update_view_entries_list() # Refresh the list display
                self.detail_label.config(text="Select an entry to view details.")
                self.current_selected_index = -1
                self.password_visible_for_index = -1
            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"Failed to delete entry from database: {e}")
                print(f"ERROR: Database delete error: {e}")
                self.conn.rollback() # <--- ROLLBACK if an error occurs


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()