import tkinter as tk
from tkinter import messagebox, simpledialog

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")

        # User storage
        self.authorized_users = {'Alice': 'password123', 'Bob': 'password456', 'Charlie': 'password789'}

        # Build the login form
        tk.Label(root, text="Username:").grid(row=0, column=0)
        self.username_entry = tk.Entry(root)
        self.username_entry.grid(row=0, column=1)

        tk.Label(root, text="Password:").grid(row=1, column=0)
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.grid(row=1, column=1)

        login_btn = tk.Button(root, text="Login", command=self.login)
        login_btn.grid(row=2, column=1, sticky=tk.W)
        register_btn = tk.Button(root, text="Register", command=self.register)
        register_btn.grid(row=2, column=1, sticky=tk.E)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username in self.authorized_users and self.authorized_users[username] == password:
            messagebox.showinfo("Login Success", "You have successfully logged in!")
            self.root.destroy()  # Close the login window
            main_app = tk.Tk()
            app = MainApplication(main_app)
            main_app.mainloop()
        else:
            messagebox.showerror("Login Failed", "Invalid username or password")

    def register(self):
        new_user = simpledialog.askstring("Register", "Enter new username:")
        new_pass = simpledialog.askstring("Register", "Enter new password:", show='*')
        if new_user and new_pass:
            self.authorized_users[new_user] = new_pass
            messagebox.showinfo("Registration Success", "You have successfully registered!")

class MainApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption/Decryption Program")

        # Encryption/Decryption Interface
        self.input_field = tk.Entry(root, width=50)
        self.input_field.pack()

        self.result_label = tk.Label(root, text="")
        self.result_label.pack()

        encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt)
        encrypt_button.pack()

        decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt)
        decrypt_button.pack()

    def encrypt(self):
        # Implement encryption logic
        plaintext = self.input_field.get()
        # Example: Simple Caesar Cipher
        ciphertext = ''.join(chr((ord(char) - 97 + 3) % 26 + 97) if 'a' <= char <= 'z' else char for char in plaintext)
        self.result_label.config(text=f"Encrypted: {ciphertext}")

    def decrypt(self):
        # Implement decryption logic
        ciphertext = self.input_field.get()
        plaintext = ''.join(chr((ord(char) - 97 - 3) % 26 + 97) if 'a' <= char <= 'z' else char for char in ciphertext)
        self.result_label.config(text=f"Decrypted: {plaintext}")

if __name__ == "__main__":
    root = tk.Tk()
    login_app = LoginWindow(root)
    root.mainloop()
