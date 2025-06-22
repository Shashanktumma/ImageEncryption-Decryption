# ImageEncryptionApp

**ImageEncryptionApp** is a Java-based desktop application built with Swing that allows users to **encrypt and decrypt image files securely** using the **AES encryption algorithm**. It **overwrites the original image file** with encrypted data, making the original image inaccessible without the correct decryption key. It supports common image formats like **JPEG, JPG, and PNG** and adds a **human-readable header** to encrypted files.

---

## ✨ Features

- 🔐 **Secure Encryption**  
  Uses `AES/CBC/PKCS5Padding` with a **256-bit key** derived using `PBKDF2WithHmacSHA256` (10,000 iterations).

- 📝 **File Overwrite**  
  Overwrites the original image file with encrypted data, retaining the **same name and extension**.

- 📃 **Encrypted File Header**  
  Adds a plain-text message at the top of encrypted files:  
  `This file is encrypted. Use ImageEncryptionApp to decrypt it.`  
  (Visible in text editors; causes image viewers to fail.)

- 🖼️ **Preview Management**  
  Clears image preview after encryption and displays a success message.

- 📂 **File Type Support**  
  Supports **JPEG, JPG, PNG** formats. Unsupported formats (e.g., **HEIC**) trigger error messages.

- 🧠 **Encrypted File Detection**  
  Recognizes encrypted files via the header, skipping image validation.

- 🖱️ **User-Friendly GUI**  
  Built with **Java Swing**: includes file chooser, password field, and dialog-based feedback.

---

## 🛠 Prerequisites

- Java Development Kit (JDK): Version 8 or higher (tested with JDK 11)
- Operating System: Windows, macOS, or Linux
- No external libraries required. Uses standard Java libraries (`javax.crypto`, `javax.imageio`, `javax.swing`)

---

## 📦 Installation

1. **Clone or Download the Project**
   ```bash
   git clone <repository-url>
   ```
   Or download the ZIP and extract it.

2. **Navigate to the Project Directory**
   ```bash
   cd ImageEncryptionApp
   ```

3. **Compile the Code**
   ```bash
   javac ImageEncryptionApp.java
   ```

4. **Run the Application**
   ```bash
   java ImageEncryptionApp
   ```

---

## 🚀 Usage

### Launch the Application

Run the compiled `.java` file to open the GUI.

### Browse for a File

- Click **Browse** to select an image (`.jpg`, `.jpeg`, `.png`) or an encrypted file.
- Valid images are previewed.
- Encrypted files show the message:  
  `Encrypted file selected: [filename]`
- Unsupported formats (e.g., `.heic`) show:  
  `Failed to load image: Unsupported image format.`

### Encrypt an Image

1. Select a valid image.
2. Enter a **password**.
3. Click **Encrypt**.
4. Image is encrypted and **overwritten**.
5. A dialog confirms:  
   `Image encrypted successfully and overwritten as [filename].`

> Open the encrypted file in a text editor to see:  
> `This file is encrypted. Use ImageEncryptionApp to decrypt it.`

> Opening in an image viewer fails with:  
> `Invalid image format`

### Decrypt an Image

1. Click **Browse** to load an encrypted file.
2. Enter the **same password** used for encryption.
3. Click **Decrypt**.
4. Image is restored, previewed, and file is **overwritten**.
5. Dialog confirms:  
   `Image decrypted and saved as [filename].`

> Incorrect passwords show:  
> `Decryption failed`

### Exit

Click **Exit** to close the app.

---

## 📄 File Format

### Encrypted File Structure

| Section           | Size         | Description                                                                 |
|-------------------|--------------|-----------------------------------------------------------------------------|
| Header            | 128 bytes    | `This file is encrypted. Use ImageEncryptionApp to decrypt it.` (padded)   |
| IV                | 16 bytes     | Initialization vector for AES-CBC                                           |
| Salt              | 16 bytes     | Salt used for PBKDF2 key derivation                                         |
| Encrypted Data    | Remaining    | AES-encrypted image bytes (PNG format internally)                           |

> ⚠️ The encrypted file retains its original name and extension, but is **not a valid image** until decrypted.

---

## 🔐 Security Notes

- Uses **AES/CBC/PKCS5Padding** with **PBKDF2WithHmacSHA256** for strong encryption.
- The original image file is **overwritten**, making it inaccessible without the correct password.
- The human-readable header is safe; the actual image content is encrypted.
- The original image data is **cleared from memory** post encryption.
- **No recovery** without the correct password — always back up files before encryption.

---

## ⚠️ Limitations

- ❌ **HEIC format not supported** without additional libraries (e.g., Apache Commons Imaging)
- 🗃️ **No automatic backup** — users must back up files manually before encryption
- ⌛ **No progress bar** for large file operations
- 📄 **Header lacks extended metadata** (e.g., file type, encryption version)

---

## 🌱 Future Improvements

- ✅ Add **HEIC support** via optional external libraries
- ✅ Implement **backup option** or warning before overwrite
- ✅ Add **progress indicators** for large files
- ✅ Enhance header with **metadata/checksum**
- ✅ Provide **GUI hints** when selecting encrypted files

---

## 🧩 Troubleshooting

### `"Failed to load image: Unsupported image format"`
- Ensure the file is a `.jpg`, `.jpeg`, or `.png` — or an encrypted file created by the app
- HEIC and other formats are not supported

### `"Decryption failed"`
- Ensure the password is correct
- Ensure the file was encrypted using this app

### `"Cannot load encrypted file"`
- Open the file in a text editor and check for the header:  
  `This file is encrypted. Use ImageEncryptionApp to decrypt it.`  
- If the header is missing or damaged, decryption may fail

---






