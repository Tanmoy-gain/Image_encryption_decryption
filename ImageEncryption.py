import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
from ttkbootstrap import Style
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Function to generate a key from a password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt image
def encrypt_image(image_path, password, output_path):
    with open(image_path, 'rb') as image_file:
        image_data = image_file.read()

    salt = os.urandom(16)
    key = generate_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_path, 'wb') as enc_file:
        enc_file.write(salt + iv + encrypted_data)

# Function to decrypt image
def decrypt_image(encrypted_path, password, output_path):
    with open(encrypted_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()

    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    key = generate_key(password, salt)
    encrypted_image_data = encrypted_data[32:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_image_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_path, 'wb') as image_file:
        image_file.write(decrypted_data)

# GUI Application
class ImageEncryptorApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()

        self.style = Style("darkly")  # Use a modern theme from ttkbootstrap
        self.title("Image Encryptor")
        self.geometry("400x300")
        self.resizable(False, False)

        # Variables
        self.image_path = tk.StringVar()
        self.password = tk.StringVar()

        # UI Elements
        self.create_widgets()

    def create_widgets(self):
        # Image Path Entry
        self.image_entry = self.create_entry_with_button("Select Image", self.image_path)
        self.image_entry.pack(pady=10)

        # Password Entry
        self.create_label("Enter Password:").pack(pady=5)
        self.password_entry = self.create_entry(self.password, show="*")
        self.password_entry.pack(pady=5)

        # Buttons
        self.create_button("Encrypt Image", self.encrypt_image).pack(pady=10)
        self.create_button("Decrypt Image", self.decrypt_image).pack(pady=5)

        # Drag and Drop Area
        self.create_label("Or Drag & Drop Image Here").pack(pady=10)
        self.drop_area = tk.Label(self, text="Drop Image Here", relief="groove", bg="#222", fg="#fff", height=5)
        self.drop_area.pack(fill="x", padx=10, pady=10)
        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind('<<Drop>>', self.drop)

    def create_entry_with_button(self, button_text, text_var):
        frame = tk.Frame(self)
        entry = tk.Entry(frame, textvariable=text_var, width=30, fg="black")
        entry.pack(side="left", padx=5)
        button = self.create_button(button_text, lambda: self.select_image(text_var),)
        button.pack(side="right")
        return frame

    def create_entry(self, text_var, **kwargs):
        return tk.Entry(self, textvariable=text_var, width=30, **kwargs)

    def create_button(self, text, command):
        return tk.Button(self, text=text, command=command, width=20, bg="#0056b3", fg="#fff", relief="flat")

    def create_label(self, text):
        return tk.Label(self, text=text, fg="#fff", bg="#222", font=("Helvetica", 12))

    def select_image(self, text_var):
        file_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp *.tiff"), ("All Files", "*.*")]
        )
        if file_path:
            text_var.set(file_path)

    def drop(self, event):
        self.image_path.set(event.data.strip("{}"))

    def encrypt_image(self):
        if not self.image_path.get() or not self.password.get():
            messagebox.showwarning("Input Error", "Please provide both an image and a password.")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if output_path:
            encrypt_image(self.image_path.get(), self.password.get(), output_path)
            messagebox.showinfo("Success", f"Image encrypted successfully!\nSaved as: {output_path}")

    def decrypt_image(self):
        if not self.image_path.get() or not self.password.get():
            messagebox.showwarning("Input Error", "Please provide both an encrypted file and a password.")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp *.tiff")])
        if output_path:
            try:
                decrypt_image(self.image_path.get(), self.password.get(), output_path)
                messagebox.showinfo("Success", f"Image decrypted successfully!\nSaved as: {output_path}")
            except Exception as e:
                messagebox.showerror("Error", "Failed to decrypt the image. Check your password or the file.")

if __name__ == "__main__":
    app = ImageEncryptorApp()
    app.mainloop()
