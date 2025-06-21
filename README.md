# 🔐 Encrypted Password Manager

A secure, desktop-based password manager built with Python and Tkinter. This application uses advanced encryption techniques to protect your sensitive login credentials while providing an intuitive user interface.

## ✨ Features

- **🔒 Advanced Encryption**: Uses AES-256 encryption with PBKDF2 key derivation
- **🛡️ Vault Key Architecture**: Implements a secure two-layer encryption system
- **👤 Master Password Protection**: Single master password to access all stored credentials
- **📝 Password Management**: Add, edit, delete, and view stored passwords
- **🎲 Password Generator**: Generate strong, random passwords
- **📋 Clipboard Integration**: Copy passwords to clipboard with auto-clear
- **🔄 Master Password Change**: Securely change master password without data loss
- **💾 SQLite Database**: Persistent storage with encrypted data
- **⌨️ Keyboard Shortcuts**: Enter key support for quick form submission

## 🏗️ Architecture

This password manager implements a **Vault Key (VK) architecture** for enhanced security:

1. **Master Password** → **Master Password Derived Key (MPDK)** via PBKDF2
2. **MPDK** → **Encrypts Vault Key (VK)** 
3. **Vault Key** → **Encrypts individual password entries**

This design ensures that changing the master password doesn't require re-encrypting all stored passwords.

## 📁 Project Structure

```
Encrypted-Password-Manager/
├── app.py                    # Main application (Tkinter GUI)
├── encryption_utils.py       # Encryption/decryption functions
├── vault.db                  # SQLite database (encrypted entries)
├── master_pass.json          # Master password hash & encrypted vault key
├── README.md                 # This file
└── .gitignore               # Git ignore rules
```

## 🚀 Installation

### Prerequisites

- Python 3.7 or higher
- Required packages: `cryptography`

### Setup

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd Encrypted-Password-Manager
   ```

2. **Install dependencies**
   ```bash
   pip install cryptography
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

## 🎯 Usage

### First Time Setup
1. Launch the application
2. Create a master password (minimum 8 characters recommended)
3. Start adding your password entries

### Daily Usage
1. Enter your master password to unlock the vault
2. Use the dashboard to:
   - **Add New Entry**: Store new login credentials
   - **Manage Entries**: View, edit, or delete existing entries
   - **Generate Password**: Create strong random passwords
   - **Change Master Password**: Update your master password securely

### Security Features
- **Auto-logout**: Vault locks when application is closed
- **Clipboard auto-clear**: Copied passwords clear after 30 seconds
- **Password visibility toggle**: Show/hide passwords as needed
- **Enter key support**: Quick form submission throughout the app

## 🎬 Demo

![appshowcase_bCI34Vjl-ezgif com-video-to-gif-converter](https://github.com/user-attachments/assets/4b8283c6-6716-4d71-8ded-dccc27b096df)


## 🔧 Technical Details

### Encryption Implementation
- **AES-256-CBC** for symmetric encryption
- **PBKDF2-HMAC-SHA256** with 100,000 iterations for key derivation
- **PKCS7 padding** for proper block alignment
- **Random IVs** for each encryption operation

### Database Schema
```sql
CREATE TABLE entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT NOT NULL,
    username TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    salt TEXT NOT NULL,
    iv TEXT NOT NULL
);
```

### File Storage
- **`vault.db`**: SQLite database containing encrypted password entries
- **`master_pass.json`**: Stores master password hash, salt, and encrypted vault key


## 🛡️ Security Considerations

- **Never share your master password**
- **Keep the application files secure**
- **Regular backups of `vault.db` and `master_pass.json`**
- **Use a strong master password**
- **Consider the security of your operating system**

## 🔄 Master Password Change Process

The application supports secure master password changes:

1. Verify current master password
2. Decrypt vault key using old master password
3. Re-encrypt vault key with new master password
4. Update stored credentials
5. All existing passwords remain accessible

## 🐛 Troubleshooting

### Common Issues

**"Master password file corrupted"**
- Delete `master_pass.json` and restart (you'll need to recreate your vault)

**"Failed to decrypt vault key"**
- Ensure you're using the correct master password
- Check if `master_pass.json` is intact

**Database errors**
- Ensure `vault.db` is not corrupted
- Check file permissions

## 📝 License

This project is for educational and personal use. Please ensure compliance with local laws and regulations regarding password management tools.

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve this password manager.
