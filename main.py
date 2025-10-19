import tkinter as tk
from tkinter import messagebox
import random, string, pyperclip

# --- Main Window ---
root = tk.Tk()
root.title("🔐 SecurePassX – Smart Password Generator")
root.geometry("520x580")
root.config(bg="#e8f0fe")

# --- Title Section ---
tk.Label(root, text="SecurePassX", font=("Poppins", 24, "bold"), fg="#0078d7", bg="#e8f0fe").pack(pady=(25, 5))
tk.Label(root, text="Generate Secure Random Passwords Easily!", font=("Arial", 11), fg="#333333", bg="#e8f0fe").pack(pady=(0, 10))

# --- Frame (Main Card Layout) ---
main_frame = tk.Frame(root, bg="#ffffff", bd=1, relief="solid", highlightbackground="#d0d0d0", highlightthickness=1)
main_frame.pack(pady=20, padx=30)

# --- Password Length Section ---
length_frame = tk.Frame(main_frame, bg="#ffffff")
length_frame.pack(pady=(20, 10))

tk.Label(length_frame, text="Password Length:", bg="#ffffff", fg="#000000",
         font=("Arial", 11, "bold")).pack(pady=(0, 5))

length_var = tk.IntVar(value=12)
tk.Scale(length_frame, from_=6, to=32, orient="horizontal", variable=length_var,
         bg="#ffffff", fg="#0078d7", troughcolor="#d0e1ff", highlightthickness=0,
         length=250).pack()

# --- Divider Line ---
tk.Frame(main_frame, height=1, bg="#dcdcdc", width=400).pack(pady=10)

# --- Options Section ---
options_frame = tk.Frame(main_frame, bg="#ffffff")
options_frame.pack(pady=(5, 15))

tk.Label(options_frame, text="Include the following in your password:", 
         bg="#ffffff", fg="#000000", font=("Arial", 11, "bold")).pack(anchor="center", pady=(0, 10))

# Variables
uppercase_var = tk.BooleanVar(value=True)
lowercase_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
special_var = tk.BooleanVar(value=False)

# Checkboxes in clear layout
checkbox_frame = tk.Frame(options_frame, bg="#ffffff")
checkbox_frame.pack()

tk.Checkbutton(checkbox_frame, text="Uppercase (A-Z)", variable=uppercase_var,
               bg="#ffffff", fg="#222222", selectcolor="#e8f0fe", font=("Arial", 10)).grid(row=0, column=0, padx=20, pady=5, sticky="w")

tk.Checkbutton(checkbox_frame, text="Lowercase (a-z)", variable=lowercase_var,
               bg="#ffffff", fg="#222222", selectcolor="#e8f0fe", font=("Arial", 10)).grid(row=0, column=1, padx=20, pady=5, sticky="w")

tk.Checkbutton(checkbox_frame, text="Digits (0-9)", variable=digits_var,
               bg="#ffffff", fg="#222222", selectcolor="#e8f0fe", font=("Arial", 10)).grid(row=1, column=0, padx=20, pady=5, sticky="w")

tk.Checkbutton(checkbox_frame, text="Special (!@#$%)", variable=special_var,
               bg="#ffffff", fg="#222222", selectcolor="#e8f0fe", font=("Arial", 10)).grid(row=1, column=1, padx=20, pady=5, sticky="w")

# --- Divider Line ---
tk.Frame(main_frame, height=1, bg="#dcdcdc", width=400).pack(pady=10)

# --- Password Output Section ---
password_label = tk.Label(main_frame, text="Generated Password:", font=("Arial", 11, "bold"),
                          fg="#333333", bg="#ffffff")
password_label.pack(pady=(5, 5))

password_entry = tk.Entry(main_frame, font=("Consolas", 16), width=30, justify="center",
                          bg="#f8faff", fg="#0078d7", relief="solid", bd=1)
password_entry.pack(pady=(5, 10))

# --- Strength Frame ---
strength_frame = tk.Frame(main_frame, bg="#ffffff", bd=1, relief="solid", highlightbackground="#cccccc")
strength_frame.pack(pady=(5, 15), padx=10, fill="x")

tk.Label(strength_frame, text="Password Strength:", font=("Arial", 10, "bold"),
         bg="#ffffff", fg="#333333").pack(side="left", padx=10, pady=6)
strength_label = tk.Label(strength_frame, text="Not generated yet", font=("Arial", 10, "bold"),
                          bg="#ffffff", fg="#666666")
strength_label.pack(side="right", padx=10)

# --- Password Generation Function ---
def generate_password():
    chars = ""
    if uppercase_var.get(): chars += string.ascii_uppercase
    if lowercase_var.get(): chars += string.ascii_lowercase
    if digits_var.get(): chars += string.digits
    if special_var.get(): chars += "!@#$%^&*()-_=+[]{};:,<.>/?"
    
    if not chars:
        messagebox.showwarning("Select Options", "Please select at least one character type!")
        return

    length = length_var.get()
    password = ''.join(random.choice(chars) for _ in range(length))
    
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    check_strength(password)

# --- Password Strength Checker ---
def check_strength(password):
    length = len(password)
    strength = "Weak"
    color = "#ff4d4d"

    if (any(c.islower() for c in password) and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password) and any(c in "!@#$%^&*()-_=+[]{};:,<.>/?"
        for c in password) and length >= 12):
        strength, color = "Strong", "#00bfa6"
    elif (any(c.isalpha() for c in password) and any(c.isdigit() for c in password)) or length >= 8:
        strength, color = "Moderate", "#ffb84d"

    strength_label.config(text=strength, fg=color)

# --- Copy to Clipboard Function ---
def copy_password():
    pwd = password_entry.get()
    if pwd:
        pyperclip.copy(pwd)
        messagebox.showinfo("Copied!", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Empty", "Please generate a password first!")

# --- Buttons ---
btn_frame = tk.Frame(root, bg="#e8f0fe")
btn_frame.pack(pady=(5, 15))

tk.Button(btn_frame, text="Generate Password", command=generate_password,
          bg="#0078d7", fg="white", font=("Arial", 12, "bold"),
          width=20, relief="flat").grid(row=0, column=0, padx=10, pady=5)

tk.Button(btn_frame, text="Copy to Clipboard", command=copy_password,
          bg="#00bfa6", fg="white", font=("Arial", 12, "bold"),
          width=20, relief="flat").grid(row=0, column=1, padx=10, pady=5)

tk.Button(root, text="Exit", command=root.quit,
          bg="#ff4d4d", fg="white", font=("Arial", 11, "bold"),
          width=18, relief="flat").pack(pady=10)

# --- Developer Credit ---
tk.Label(root, text="© 2025 SecurePassX | Developed by Jogi Naidu 🧠",
         font=("Arial", 9, "italic"), fg="#444444", bg="#e8f0fe").pack(side="bottom", pady=10)

# --- Run App ---
root.mainloop()
