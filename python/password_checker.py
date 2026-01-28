import tkinter as tk
from tkinter import ttk
import random
import string
import re

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))


def evaluate_password(password):
    score = 0
    tips = []

    checks = [
        (len(password) >= 8, "Use at least 8 characters"),
        (re.search(r"[A-Z]", password), "Add uppercase letters"),
        (re.search(r"[a-z]", password), "Add lowercase letters"),
        (re.search(r"\d", password), "Add numbers"),
        (re.search(r"[!@#$%^&*(),.?\":{}|<>]", password), "Add special characters"),
    ]

    for condition, tip in checks:
        if condition:
            score += 1
        else:
            tips.append(tip)

    return score, tips


def check_password():
    password = password_entry.get()
    score, tips = evaluate_password(password)

    progress['value'] = score * 20

    if score <= 2:
        result_label.config(text="Weak Password", fg="red")
    elif score <= 4:
        result_label.config(text="Medium Password", fg="orange")
    else:
        result_label.config(text="Strong Password", fg="green")

    tips_box.delete(1.0, tk.END)
    if tips:
        for tip in tips:
            tips_box.insert(tk.END, f"• {tip}\n")
    else:
        tips_box.insert(tk.END, "Password looks secure 👍")


def generate_and_check():
    pwd = generate_password()
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




root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("520x460")
root.resizable(False, False)

style = ttk.Style()
style.theme_use("default")
style.configure("Strength.Horizontal.TProgressbar", thickness=18)

tk.Label(
    root,
    text="Password Strength Checker",
    font=("Segoe UI", 18, "bold")
).pack(pady=15)

tk.Label(
    root,
    text="Enter Password",
    font=("Segoe UI", 11)
).pack(anchor="w", padx=50)

entry_frame = tk.Frame(root)
entry_frame.pack(pady=5)

password_entry = tk.Entry(
    entry_frame,
    show="*",
    font=("Segoe UI", 12),
    width=26
)
password_entry.pack(side=tk.LEFT, ipady=4)

eye_btn = tk.Button(
    entry_frame,
    text="👁",
    command=toggle_password,
    relief="flat"
)
eye_btn.pack(side=tk.LEFT, padx=5)

progress = ttk.Progressbar(
    root,
    length=380,
    maximum=100,
    style="Strength.Horizontal.TProgressbar"
)
progress.pack(pady=15)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

tk.Button(
    btn_frame,
    text="Check Strength",
    command=check_password,
    bg="#007bff",
    fg="white",
    width=15
).pack(side=tk.LEFT, padx=5)

tk.Button(
    btn_frame,
    text="Generate Password",
    command=generate_and_check,
    bg="#28a745",
    fg="white",
    width=18
).pack(side=tk.LEFT, padx=5)

result_label = tk.Label(
    root,
    text="Password Strength",
    font=("Segoe UI", 13, "bold")
)
result_label.pack(pady=10)

tk.Label(
    root,
    text="Suggestions",
    font=("Segoe UI", 11)
).pack(anchor="w", padx=50)

tips_box = tk.Text(
    root,
    height=4,
    width=50,
    font=("Segoe UI", 10),
    relief="solid"
)
tips_box.pack(pady=5)

root.mainloop()
