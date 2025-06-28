import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os
import random
import string
import re
import datetime
import json
from itertools import product
import hashlib
from ttkbootstrap import Style
from ttkbootstrap.constants import *

class PasswordCrackingLab:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Cracking Lab")
        self.root.geometry("900x700")
        self.style = Style(theme="darkly")  # Using ttkbootstrap for modern look
        self.setup_gui()

    def setup_gui(self):
        # Main container
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill="both", expand=True)

        # Header
        header = ttk.Label(self.main_frame, text="Password Cracking Lab", font=("Helvetica", 24, "bold"), bootstyle="primary")
        header.pack(pady=10)

        # Notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame, bootstyle="primary")
        self.notebook.pack(pady=10, fill="both", expand=True)

        # Cracking Engine Tab
        self.cracking_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.cracking_frame, text="Cracking Engine")
        self.setup_cracking_engine()

        # Wordlist Generator Tab
        self.wordlist_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.wordlist_frame, text="Wordlist Generator")
        self.setup_wordlist_generator()

        # Password Policy Analyzer Tab
        self.policy_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.policy_frame, text="Policy Analyzer")
        self.setup_policy_analyzer()

        # Report Builder Tab
        self.report_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.report_frame, text="Report Builder")
        self.setup_report_builder()

        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, bootstyle="inverse-primary")
        status_bar.pack(side="bottom", fill="x", pady=5)

    def create_tooltip(self, widget, text):
        """Create a tooltip for a given widget."""
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)  # Remove window decorations
        tooltip.wm_geometry("+0+0")  # Position will be updated dynamically
        label = tk.Label(tooltip, text=text, background="yellow", relief="solid", borderwidth=1, font=("Helvetica", 10))
        label.pack()

        tooltip.withdraw()  # Hide initially

        def show_tooltip(event):
            tooltip.wm_deiconify()  # Show tooltip
            x = event.x_root + 20  # Position slightly to the right of cursor
            y = event.y_root + 10  # Position slightly below cursor
            tooltip.wm_geometry(f"+{x}+{y}")

        def hide_tooltip(event):
            tooltip.wm_withdraw()  # Hide tooltip

        widget.bind("<Enter>", show_tooltip)
        widget.bind("<Leave>", hide_tooltip)

    def add_button_hover_effect(self, button):
        """Add hover effect to a button."""
        original_style = button.cget("style") or "TButton"
        hover_style = f"{original_style}.Hover"

        # Configure hover style (lighter background)
        self.style.configure(hover_style, background="#4CAF50")  # Greenish hover color for success buttons
        button.bind("<Enter>", lambda e: button.configure(style=hover_style))
        button.bind("<Leave>", lambda e: button.configure(style=original_style))

        # Configure button styles
        self.style.configure("TButton", padding=6, relief="flat")
        self.style.configure("TLabel", padding=6)

    def setup_cracking_engine(self):
        # Frame for inputs
        input_frame = ttk.LabelFrame(self.cracking_frame, text="Cracking Settings", bootstyle="primary", padding=10)
        input_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Hash Type Selection
        ttk.Label(input_frame, text="Hash Type:", font=("Helvetica", 10)).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.hash_type = ttk.Combobox(input_frame, values=["md5", "sha1", "sha256", "ntlm", "bcrypt"], bootstyle="secondary", width=30)
        self.hash_type.set("md5")
        self.hash_type.grid(row=0, column=1, padx=5, pady=5)
        self.create_tooltip(self.hash_type, "Select the type of hash to crack")

        # Hash Input
        ttk.Label(input_frame, text="Enter Hash:", font=("Helvetica", 10)).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.hash_input = ttk.Entry(input_frame, width=50, bootstyle="secondary")
        self.hash_input.grid(row=1, column=1, padx=5, pady=5)
        self.create_tooltip(self.hash_input, "Enter the hash value to crack")

        # Wordlist File
        ttk.Label(input_frame, text="Wordlist File:", font=("Helvetica", 10)).grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.wordlist_path = ttk.Entry(input_frame, width=50, bootstyle="secondary")
        self.wordlist_path.grid(row=2, column=1, padx=5, pady=5)
        browse_button = ttk.Button(input_frame, text="Browse", command=self.browse_wordlist, bootstyle="outline-secondary")
        browse_button.grid(row=2, column=2, padx=5, pady=5)
        self.create_tooltip(self.wordlist_path, "Path to the wordlist file")
        self.create_tooltip(browse_button, "Browse for a wordlist file")
        self.add_button_hover_effect(browse_button)

        # Cracker Selection
        ttk.Label(input_frame, text="Cracker:", font=("Helvetica", 10)).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.cracker_type = ttk.Combobox(input_frame, values=["Hashcat", "John the Ripper"], bootstyle="secondary", width=30)
        self.cracker_type.set("Hashcat")
        self.cracker_type.grid(row=3, column=1, padx=5, pady=5)
        self.create_tooltip(self.cracker_type, "Select the cracking tool to use")

        # Progress Bar
        self.progress = ttk.Progressbar(self.cracking_frame, mode="indeterminate", bootstyle="striped-success")
        self.progress.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

        # Output Display
        output_frame = ttk.LabelFrame(self.cracking_frame, text="Cracking Output", bootstyle="primary", padding=10)
        output_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)
        self.crack_output = tk.Text(output_frame, height=12, width=70, wrap="word", font=("Courier", 10))
        self.crack_output.pack(padx=5, pady=5, fill="both", expand=True)
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.crack_output.yview, bootstyle="round")
        scrollbar.pack(side="right", fill="y")
        self.crack_output.config(yscrollcommand=scrollbar.set)

        # Start Button
        start_button = ttk.Button(self.cracking_frame, text="Start Cracking", command=self.start_cracking, bootstyle="success")
        start_button.grid(row=3, column=0, pady=15)
        self.create_tooltip(start_button, "Start the password cracking process")
        self.add_button_hover_effect(start_button)

        self.cracking_frame.grid_columnconfigure(0, weight=1)
        self.cracking_frame.grid_rowconfigure(2, weight=1)

    def setup_wordlist_generator(self):
        # Frame for inputs
        input_frame = ttk.LabelFrame(self.wordlist_frame, text="Wordlist Settings", bootstyle="primary", padding=10)
        input_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Keywords Input
        ttk.Label(input_frame, text="Keywords (comma-separated):", font=("Helvetica", 10)).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.keywords = ttk.Entry(input_frame, width=50, bootstyle="secondary")
        self.keywords.grid(row=0, column=1, padx=5, pady=5)
        self.create_tooltip(self.keywords, "Enter keywords separated by commas")

        # Length Range
        ttk.Label(input_frame, text="Password Length (min-max):", font=("Helvetica", 10)).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.min_length = ttk.Entry(input_frame, width=10, bootstyle="secondary")
        self.min_length.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.max_length = ttk.Entry(input_frame, width=10, bootstyle="secondary")
        self.max_length.grid(row=1, column=1, padx=60, pady=5, sticky="w")
        self.create_tooltip(self.min_length, "Minimum password length")
        self.create_tooltip(self.max_length, "Maximum password length")

        # Character Sets
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_special = tk.BooleanVar(value=True)
        lowercase_cb = ttk.Checkbutton(input_frame, text="Lowercase", variable=self.use_lowercase)
        lowercase_cb.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        uppercase_cb = ttk.Checkbutton(input_frame, text="Uppercase", variable=self.use_uppercase)
        uppercase_cb.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        digits_cb = ttk.Checkbutton(input_frame, text="Digits", variable=self.use_digits)
        digits_cb.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        special_cb = ttk.Checkbutton(input_frame, text="Special Characters", variable=self.use_special)
        special_cb.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        self.create_tooltip(lowercase_cb, "Include lowercase letters (a-z)")
        self.create_tooltip(uppercase_cb, "Include uppercase letters (A-Z)")
        self.create_tooltip(digits_cb, "Include digits (0-9)")
        self.create_tooltip(special_cb, "Include special characters (e.g., !@#$%)")

        # Output File
        ttk.Label(input_frame, text="Output Wordlist File:", font=("Helvetica", 10)).grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.wordlist_output = ttk.Entry(input_frame, width=50, bootstyle="secondary")
        self.wordlist_output.grid(row=4, column=1, padx=5, pady=5)
        browse_button = ttk.Button(input_frame, text="Browse", command=self.browse_wordlist_output, bootstyle="outline-secondary")
        browse_button.grid(row=4, column=2, padx=5, pady=5)
        self.create_tooltip(self.wordlist_output, "Path to save the generated wordlist")
        self.create_tooltip(browse_button, "Browse to select output file location")
        self.add_button_hover_effect(browse_button)

        # Generate Button
        generate_button = ttk.Button(self.wordlist_frame, text="Generate Wordlist", command=self.generate_wordlist, bootstyle="success")
        generate_button.grid(row=1, column=0, pady=15)
        self.create_tooltip(generate_button, "Generate a wordlist based on the settings")
        self.add_button_hover_effect(generate_button)

        self.wordlist_frame.grid_columnconfigure(0, weight=1)

    def setup_policy_analyzer(self):
        # Frame for inputs
        input_frame = ttk.LabelFrame(self.policy_frame, text="Policy Settings", bootstyle="primary", padding=10)
        input_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Password Input
        ttk.Label(input_frame, text="Password to Analyze:", font=("Helvetica", 10)).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.password_input = ttk.Entry(input_frame, width=50, bootstyle="secondary", show="*")
        self.password_input.grid(row=0, column=1, padx=5, pady=5)
        self.create_tooltip(self.password_input, "Enter the password to analyze")

        # Policy Settings
        ttk.Label(input_frame, text="Min Length:", font=("Helvetica", 10)).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.min_length_policy = ttk.Entry(input_frame, width=10, bootstyle="secondary")
        self.min_length_policy.insert(0, "8")
        self.min_length_policy.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.create_tooltip(self.min_length_policy, "Minimum required password length")

        self.require_upper = tk.BooleanVar(value=True)
        self.require_lower = tk.BooleanVar(value=True)
        self.require_digit = tk.BooleanVar(value=True)
        self.require_special = tk.BooleanVar(value=True)
        upper_cb = ttk.Checkbutton(input_frame, text="Require Uppercase", variable=self.require_upper)
        upper_cb.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        lower_cb = ttk.Checkbutton(input_frame, text="Require Lowercase", variable=self.require_lower)
        lower_cb.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        digit_cb = ttk.Checkbutton(input_frame, text="Require Digit", variable=self.require_digit)
        digit_cb.grid(row=3, column=0, padx=5, pady=5, sticky="w")
        special_cb = ttk.Checkbutton(input_frame, text="Require Special Character", variable=self.require_special)
        special_cb.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        self.create_tooltip(upper_cb, "Require at least one uppercase letter")
        self.create_tooltip(lower_cb, "Require at least one lowercase letter")
        self.create_tooltip(digit_cb, "Require at least one digit")
        self.create_tooltip(special_cb, "Require at least one special character")

        # Generate Strong Password Button
        generate_button = ttk.Button(input_frame, text="Generate Strong Password", command=self.generate_and_display_password, bootstyle="info")
        generate_button.grid(row=4, column=0, columnspan=2, pady=10)
        self.create_tooltip(generate_button, "Generate a strong password")
        self.add_button_hover_effect(generate_button)

        # Analysis Output
        output_frame = ttk.LabelFrame(self.policy_frame, text="Analysis Results", bootstyle="primary", padding=10)
        output_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.policy_output = tk.Text(output_frame, height=12, width=70, wrap="word", font=("Courier", 10))
        self.policy_output.pack(padx=5, pady=5, fill="both", expand=True)
        scrollbar = ttk.Scrollbar(output_frame, orient="vertical", command=self.policy_output.yview, bootstyle="round")
        scrollbar.pack(side="right", fill="y")
        self.policy_output.config(yscrollcommand=scrollbar.set)

        # Analyze Button
        analyze_button = ttk.Button(self.policy_frame, text="Analyze Password", command=self.analyze_password, bootstyle="success")
        analyze_button.grid(row=2, column=0, pady=5)
        self.create_tooltip(analyze_button, "Analyze the entered password")
        self.add_button_hover_effect(analyze_button)

        # Copy to Clipboard Button (initially hidden)
        self.copy_button = ttk.Button(self.policy_frame, text="Copy Password", command=self.copy_to_clipboard, bootstyle="secondary")
        self.copy_button.grid(row=3, column=0, pady=5)
        self.copy_button.grid_remove()  # Hide initially
        self.create_tooltip(self.copy_button, "Copy the suggested password to clipboard")
        self.add_button_hover_effect(self.copy_button)

        self.policy_frame.grid_columnconfigure(0, weight=1)
        self.policy_frame.grid_rowconfigure(1, weight=1)

    def setup_report_builder(self):
        # Frame for report
        input_frame = ttk.LabelFrame(self.report_frame, text="Report Content", bootstyle="primary", padding=10)
        input_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.report_content = tk.Text(input_frame, height=15, width=70, wrap="word", font=("Courier", 10))
        self.report_content.pack(padx=5, pady=5, fill="both", expand=True)
        scrollbar = ttk.Scrollbar(input_frame, orient="vertical", command=self.report_content.yview, bootstyle="round")
        scrollbar.pack(side="right", fill="y")
        self.report_content.config(yscrollcommand=scrollbar.set)

        # Report File
        ttk.Label(self.report_frame, text="Report File Name:", font=("Helvetica", 10)).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.report_file = ttk.Entry(self.report_frame, width=50, bootstyle="secondary")
        self.report_file.grid(row=1, column=1, padx=5, pady=5)
        browse_button = ttk.Button(self.report_frame, text="Browse", command=self.browse_report_file, bootstyle="outline-secondary")
        browse_button.grid(row=1, column=2, padx=5, pady=5)
        self.create_tooltip(self.report_file, "Path to save the report")
        self.create_tooltip(browse_button, "Browse to select report file location")
        self.add_button_hover_effect(browse_button)

        # Generate Report Button
        generate_button = ttk.Button(self.report_frame, text="Generate Report", command=self.generate_report, bootstyle="success")
        generate_button.grid(row=2, column=1, pady=15)
        self.create_tooltip(generate_button, "Generate and save the report")
        self.add_button_hover_effect(generate_button)

        self.report_frame.grid_columnconfigure(0, weight=1)
        self.report_frame.grid_rowconfigure(0, weight=1)

    def browse_wordlist(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file:
            self.wordlist_path.delete(0, tk.END)
            self.wordlist_path.insert(0, file)
            self.status_var.set(f"Selected wordlist: {os.path.basename(file)}")

    def browse_wordlist_output(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            self.wordlist_output.delete(0, tk.END)
            self.wordlist_output.insert(0, file)
            self.status_var.set(f"Selected output: {os.path.basename(file)}")

    def browse_report_file(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file:
            self.report_file.delete(0, tk.END)
            self.report_file.insert(0, file)
            self.status_var.set(f"Selected report file: {os.path.basename(file)}")

    def start_cracking(self):
        hash_value = self.hash_input.get()
        wordlist = self.wordlist_path.get()
        cracker = self.cracker_type.get()
        hash_type = self.hash_type.get()

        if not hash_value or not wordlist:
            messagebox.showerror("Error", "Please provide hash and wordlist file.", bootstyle="danger")
            return

        self.status_var.set("Starting cracking process...")
        self.progress.start()

        # Save hash to a temporary file
        with open("temp_hash.txt", "w") as f:
            f.write(hash_value)

        try:
            if cracker == "Hashcat":
                cmd = f"hashcat -m {self.get_hashcat_mode(hash_type)} -a 0 temp_hash.txt {wordlist}"
            else:  # John the Ripper
                john_path = r"D:\Intern\john\run\john.exe"  # <-- Update this path as needed
                john_format = self.get_john_format(hash_type)
                cmd = f'"{john_path}" --format={john_format} --wordlist="{wordlist}" temp_hash.txt'

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            self.crack_output.delete(1.0, tk.END)
            self.crack_output.insert(tk.END, result.stdout + result.stderr)

            # Check for cracked passwords
            if cracker == "Hashcat":
                cracked = subprocess.run(f"hashcat -m {self.get_hashcat_mode(hash_type)} temp_hash.txt --show",
                                        shell=True, capture_output=True, text=True)
                self.crack_output.insert(tk.END, "\nCracked Passwords:\n" + cracked.stdout)
            else:
                cracked = subprocess.run(f'"{john_path}" --show temp_hash.txt', shell=True, capture_output=True, text=True)
                self.crack_output.insert(tk.END, "\nCracked Passwords:\n" + cracked.stdout)

            self.status_var.set("Cracking completed!")
        except Exception as e:
            messagebox.showerror("Error", f"Cracking failed: {str(e)}", bootstyle="danger")
            self.status_var.set("Cracking failed")
        finally:
            self.progress.stop()

    def get_hashcat_mode(self, hash_type):
        modes = {"md5": "0", "sha1": "100", "sha256": "1400", "ntlm": "1000", "bcrypt": "3200"}
        return modes.get(hash_type, "0")

    def get_john_format(self, hash_type):
        formats = {"md5": "md5", "sha1": "raw-sha1", "sha256": "raw-sha256", "ntlm": "ntlm", "bcrypt": "bcrypt"}
        return formats.get(hash_type, "md5")

    def generate_wordlist(self):
        keywords = self.keywords.get().split(",")
        try:
            min_len = int(self.min_length.get())
            max_len = int(self.max_length.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter valid min and max lengths.", bootstyle="danger")
            return

        output_file = self.wordlist_output.get()
        if not output_file:
            messagebox.showerror("Error", "Please specify an output file.", bootstyle="danger")
            return

        chars = ""
        if self.use_lowercase.get():
            chars += string.ascii_lowercase
        if self.use_uppercase.get():
            chars += string.ascii_uppercase
        if self.use_digits.get():
            chars += string.digits
        if self.use_special.get():
            chars += string.punctuation

        if not chars:
            messagebox.showerror("Error", "Please select at least one character set.", bootstyle="danger")
            return

        self.status_var.set("Generating wordlist...")
        try:
            with open(output_file, "w") as f:
                for keyword in keywords:
                    keyword = keyword.strip()
                    if keyword:
                        f.write(keyword + "\n")
                        f.write(keyword.capitalize() + "\n")
                        f.write(keyword.upper() + "\n")
                        f.write(keyword + "123" + "\n")
                        f.write(keyword + "!" + "\n")

                for length in range(min_len, max_len + 1):
                    for combo in product(chars, repeat=length):
                        f.write("".join(combo) + "\n")

            messagebox.showinfo("Success", f"Wordlist generated at {output_file}", bootstyle="success")
            self.status_var.set("Wordlist generation completed!")
        except Exception as e:
            messagebox.showerror("Error", f"Wordlist generation failed: {str(e)}", bootstyle="danger")
            self.status_var.set("Wordlist generation failed")

    def generate_strong_password(self, length=12):
        """Generate a strong password with mixed characters."""
        if length < 8:
            length = 8  # Ensure minimum length for strength
        chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        password = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice(string.punctuation)
        ]
        for _ in range(length - 4):
            password.append(random.choice(chars))
        random.shuffle(password)
        return "".join(password)

    def generate_and_display_password(self):
        """Generate a strong password and display it in the output."""
        strong_password = self.generate_strong_password()
        self.policy_output.delete(1.0, tk.END)
        self.policy_output.insert(tk.END, f"Generated Strong Password: {strong_password}\n")
        self.suggested_password = strong_password  # Store for copying
        self.copy_button.grid()  # Show the copy button
        self.status_var.set("Strong password generated")

    def copy_to_clipboard(self):
        """Copy the suggested password to the clipboard."""
        if hasattr(self, 'suggested_password'):
            self.root.clipboard_clear()
            self.root.clipboard_append(self.suggested_password)
            messagebox.showinfo("Success", "Password copied to clipboard!", bootstyle="success")
            self.status_var.set("Password copied to clipboard")
        else:
            messagebox.showerror("Error", "No password to copy!", bootstyle="danger")

    def analyze_password(self):
        password = self.password_input.get()
        min_length = int(self.min_length_policy.get() or 8)
        issues = []

        if len(password) < min_length:
            issues.append(f"Password is too short (minimum {min_length} characters)")
        if self.require_upper.get() and not re.search(r"[A-Z]", password):
            issues.append("Password must contain at least one uppercase letter")
        if self.require_lower.get() and not re.search(r"[a-z]", password):
            issues.append("Password must contain at least one lowercase letter")
        if self.require_digit.get() and not re.search(r"\d", password):
            issues.append("Password must contain at least one digit")
        if self.require_special.get() and not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            issues.append("Password must contain at least one special character")

        strength = self.estimate_password_strength(password)
        self.policy_output.delete(1.0, tk.END)
        if issues:
            self.policy_output.insert(tk.END, "Issues found:\n" + "\n".join(issues) + f"\n\nStrength: {strength}\n")
        else:
            self.policy_output.insert(tk.END, f"Password meets all requirements.\nStrength: {strength}\n")

        # Suggest a strong password if strength is Weak or Moderate
        if strength in ["Weak", "Moderate"]:
            strong_password = self.generate_strong_password()
            self.policy_output.insert(tk.END, f"\nSuggested Strong Password: {strong_password}\n")
            self.suggested_password = strong_password  # Store for copying
            self.copy_button.grid()  # Show the copy button
        else:
            self.copy_button.grid_remove()  # Hide the copy button if no suggestion

        self.status_var.set("Password analysis completed")

    def estimate_password_strength(self, password):
        score = len(password) * 4
        if re.search(r"[A-Z]", password):
            score += 10
        if re.search(r"[a-z]", password):
            score += 10
        if re.search(r"\d", password):
            score += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 10
        if len(set(password)) / len(password) > 0.7:
            score += 10

        if score < 50:
            return "Weak"
        elif score < 80:
            return "Moderate"
        else:
            return "Strong"

    def generate_report(self):
        report_file = self.report_file.get()
        if not report_file:
            messagebox.showerror("Error", "Please specify a report file.", bootstyle="danger")
            return

        self.report_content.delete(1.0, tk.END)
        report_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "cracking_results": self.crack_output.get(1.0, tk.END).strip(),
            "wordlist_settings": {
                "keywords": self.keywords.get(),
                "min_length": self.min_length.get(),
                "max_length": self.max_length.get(),
                "character_sets": {
                    "lowercase": self.use_lowercase.get(),
                    "uppercase": self.use_uppercase.get(),
                    "digits": self.use_digits.get(),
                    "special": self.use_special.get()
                }
            },
            "policy_analysis": self.policy_output.get(1.0, tk.END).strip()
        }
        self.report_content.insert(tk.END, json.dumps(report_data, indent=4))

        try:
            with open(report_file, "w") as f:
                json.dump(report_data, f, indent=4)
            messagebox.showinfo("Success", f"Report generated at {report_file}", bootstyle="success")
            self.status_var.set("Report generated successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed: {str(e)}", bootstyle="danger")
            self.status_var.set("Report generation failed")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCrackingLab(root)
    root.mainloop()
