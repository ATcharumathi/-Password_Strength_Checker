import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import re


def generate_password(length=16):
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.<>?/"

    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
    ]

    all_chars = uppercase + lowercase + digits + symbols
    password += random.choices(all_chars, k=length - 4)

    random.shuffle(password)
    return ''.join(password)


def evaluate_password(password):
    score = 0
    tips = []

    checks = [
        (len(password) >= 8, "Use at least 8 characters"),
        (len(password) >= 12, "Use 12 or more characters"),
        (re.search(r"[A-Z]", password), "Add uppercase letters"),
        (re.search(r"[a-z]", password), "Add lowercase letters"),
        (re.search(r"\d", password), "Add numbers"),
        (re.search(r"[!@#$%^&*()\-_=+\[\]{};:,.<>?/]", password), "Add special characters"),
        (not re.search(r"(.)\1{2,}", password), "Avoid repeated characters"),
    ]

    for condition, tip in checks:
        if condition:
            score += 1
        else:
            tips.append(tip)

    return score, tips


def check_password(event=None):
    password = password_entry.get()
    score, tips = evaluate_password(password)

    percentage = int((score / 7) * 100)
    progress["value"] = percentage

    if score <= 3:
        result_label.config(text="Weak Password", fg="#dc3545")
        progress_style.configure("Strength.Horizontal.TProgressbar", background="#dc3545")
    elif score <= 5:
        result_label.config(text="Medium Password", fg="#ffc107")
        progress_style.configure("Strength.Horizontal.TProgressbar", background="#ffc107")
    else:
        result_label.config(text="Strong Password", fg="#28a745")
        progress_style.configure("Strength.Horizontal.TProgressbar", background="#28a745")

    tips_box.config(state=tk.NORMAL)
    tips_box.delete(1.0, tk.END)

    if not password:
        tips_box.insert(tk.END, "Enter a password to check strength.")
    elif tips:
        for tip in tips:
            tips_box.insert(tk.END, f"• {tip}\n")
    else:
        tips_box.insert(tk.END, "Password looks secure 👍")

    tips_box.config(state=tk.DISABLED)


def generate_and_check():
    length = length_var.get()
    pwd = generate_password(length)

    password_entry.delete(0, tk.END)
    password_entry.insert(0, pwd)

    check_password()


def toggle_password():
    if password_entry.cget("show") == "*":
        password_entry.config(show="")
        eye_btn.config(text="🙈")
    else:
        password_entry.config(show="*")
        eye_btn.config(text="👁")


def copy_password():
    password = password_entry.get()

    if password:
        root.clipboard_clear()
        root.clipboard_append(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Empty", "No password to copy.")


root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("560x520")
root.resizable(False, False)
root.configure(bg="#f4f6f8")

progress_style = ttk.Style()
progress_style.theme_use("default")
progress_style.configure(
    "Strength.Horizontal.TProgressbar",
    thickness=18,
    background="#dc3545"
)

title = tk.Label(
    root,
    text="Password Strength Checker",
    font=("Segoe UI", 20, "bold"),
    bg="#f4f6f8",
    fg="#222"
)
title.pack(pady=20)

tk.Label(
    root,
    text="Enter Password",
    font=("Segoe UI", 11, "bold"),
    bg="#f4f6f8"
).pack(anchor="w", padx=60)

entry_frame = tk.Frame(root, bg="#f4f6f8")
entry_frame.pack(pady=8)

password_entry = tk.Entry(
    entry_frame,
    show="*",
    font=("Segoe UI", 12),
    width=30,
    relief="solid",
    bd=1
)
password_entry.pack(side=tk.LEFT, ipady=6)

password_entry.bind("<KeyRelease>", check_password)

eye_btn = tk.Button(
    entry_frame,
    text="👁",
    command=toggle_password,
    relief="flat",
    font=("Segoe UI", 11),
    bg="#f4f6f8"
)
eye_btn.pack(side=tk.LEFT, padx=6)

progress = ttk.Progressbar(
    root,
    length=420,
    maximum=100,
    style="Strength.Horizontal.TProgressbar"
)
progress.pack(pady=15)

length_frame = tk.Frame(root, bg="#f4f6f8")
length_frame.pack(pady=5)

tk.Label(
    length_frame,
    text="Password Length:",
    font=("Segoe UI", 10, "bold"),
    bg="#f4f6f8"
).pack(side=tk.LEFT, padx=5)

length_var = tk.IntVar(value=16)

length_spinbox = tk.Spinbox(
    length_frame,
    from_=8,
    to=32,
    textvariable=length_var,
    width=5,
    font=("Segoe UI", 10)
)
length_spinbox.pack(side=tk.LEFT)

btn_frame = tk.Frame(root, bg="#f4f6f8")
btn_frame.pack(pady=12)

tk.Button(
    btn_frame,
    text="Check Strength",
    command=check_password,
    bg="#007bff",
    fg="white",
    activebackground="#0056b3",
    activeforeground="white",
    width=15,
    relief="flat",
    font=("Segoe UI", 10, "bold")
).pack(side=tk.LEFT, padx=5)

tk.Button(
    btn_frame,
    text="Generate Password",
    command=generate_and_check,
    bg="#28a745",
    fg="white",
    activebackground="#1e7e34",
    activeforeground="white",
    width=18,
    relief="flat",
    font=("Segoe UI", 10, "bold")
).pack(side=tk.LEFT, padx=5)

tk.Button(
    btn_frame,
    text="Copy",
    command=copy_password,
    bg="#6c757d",
    fg="white",
    activebackground="#545b62",
    activeforeground="white",
    width=10,
    relief="flat",
    font=("Segoe UI", 10, "bold")
).pack(side=tk.LEFT, padx=5)

result_label = tk.Label(
    root,
    text="Password Strength",
    font=("Segoe UI", 14, "bold"),
    bg="#f4f6f8",
    fg="#333"
)
result_label.pack(pady=10)

tk.Label(
    root,
    text="Suggestions",
    font=("Segoe UI", 11, "bold"),
    bg="#f4f6f8"
).pack(anchor="w", padx=60)

tips_box = tk.Text(
    root,
    height=5,
    width=55,
    font=("Segoe UI", 10),
    relief="solid",
    bd=1,
    wrap=tk.WORD
)
tips_box.pack(pady=8)
tips_box.insert(tk.END, "Enter a password to check strength.")
tips_box.config(state=tk.DISABLED)

root.mainloop()
