#!/usr/bin/env python3
import socket
import sys
import requests
import hashlib
import re
import math
import tkinter as tk
from tkinter import messagebox, simpledialog

def port_scanner(target_host, start_port, end_port):
    """
    Basic port scanner that identifies active services
    """
    result = []
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        return "Host name could not be resolved"
    
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result_code = sock.connect_ex((target_ip, port))
        if result_code == 0:
            result.append(f"Port {port}: Open")
        sock.close()
    return "\n".join(result) if result else "No open ports found"

def check_sql_injection(url):
    """
    Basic test for SQL injection
    """
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR '1'='1'/*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' OR 'x'='x",
        "' OR 'a'='a"
    ]
    
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        
        if "error" in response.text.lower() or "mysql" in response.text.lower():
            return f"Potential SQL injection vulnerability found with payload: {payload}"
    return "No SQL injection vulnerabilities found"

def password_strength_checker(password):
    """
    Password strength analyzer with advanced word checking
    """
    score = 0
    findings = []
    
    common_words = {
        "password", "qwerty", "admin", "user", "login", "welcome", "abc123",
        "test", "guest", "12345", "54321", "11111", "00000",
        "ciao", "casa", "amore", "vita", "sole", "luna", "mare", "terra",
        "cielo", "fuoco", "acqua", "aria", "tempo", "giorno", "notte",
        "inverno", "estate", "autunno", "primavera",
        "mario", "luigi", "giovanni", "paolo", "marco", "andrea", "giuseppe",
        "antonio", "maria", "anna", "laura", "sara", "giulia", "rosa",
        "admin", "root", "user", "guest", "test", "demo", "login",
        "password", "system", "database", "server", "client", "network",
        "lunedi", "martedi", "mercoledi", "giovedi", "venerdi", "sabato", "domenica",
        "gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno",
        "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"
    }
    
    extended_words = set()
    for word in common_words:
        extended_words.add(word.lower())
        extended_words.add(word.upper())
        extended_words.add(word.capitalize())
    common_words = extended_words
    
    def contains_common_word(pwd):
        for i in range(len(pwd) - 3):
            for j in range(i + 4, len(pwd) + 1):
                if pwd[i:j].lower() in common_words:
                    return True
        return False
    
    if len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        findings.append("Password too short (minimum 8 characters, recommended 16+)")
    
    num_count = len(re.findall(r"\d", password))
    if num_count >= 3:
        score += 2
    elif num_count >= 2:
        score += 1
    else:
        findings.append("At least 2 numbers required (recommended 3+)")
    
    upper_count = len(re.findall(r"[A-Z]", password))
    if upper_count >= 3:
        score += 2
    elif upper_count >= 2:
        score += 1
    else:
        findings.append("At least 2 uppercase letters required (recommended 3+)")
    
    lower_count = len(re.findall(r"[a-z]", password))
    if lower_count >= 3:
        score += 2
    elif lower_count >= 2:
        score += 1
    else:
        findings.append("At least 2 lowercase letters required (recommended 3+)")
    
    special_chars = "!@#$%^&*(),.?\":{}|<>_+-=[]\\/"
    special_count = len([c for c in password if c in special_chars])
    if special_count >= 3:
        score += 2
    elif special_count >= 1:
        score += 1
    else:
        findings.append("At least 1 special character required (recommended 3+)")
    
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        findings.append("Avoid consecutive repeated characters")
    
    sequences = ["123", "234", "345", "456", "567", "678", "789", "987", "876", 
                "765", "654", "543", "432", "321", "abc", "bcd", "cde", "def"]
    if any(seq in password.lower() for seq in sequences):
        score -= 1
        findings.append("Avoid numerical or alphabetical sequences")
    
    if contains_common_word(password):
        score = max(0, score - 3)
        findings.append("Password contains common words - very risky")
    
    char_set_size = (
        (1 if re.search(r'[a-z]', password) else 0) * 26 +
        (1 if re.search(r'[A-Z]', password) else 0) * 26 +
        (1 if re.search(r'\d', password) else 0) * 10 +
        len([c for c in password if c in special_chars])
    )
    entropy = math.log2(char_set_size) * len(password) if char_set_size > 0 else 0
    
    findings.append(f"Password entropy: {entropy:.2f} bits")
    
    if contains_common_word(password):
        strength_level = min(1, score // 2)
    else:
        strength_level = min(4, score // 2)
    
    strength_labels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    
    return {
        "score": max(score, 0),
        "strength": strength_labels[strength_level],
        "findings": findings,
        "entropy": entropy
    }

def xss_scanner(url):
    """
    Basic XSS scanner
    """
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>"
    ]
    
    for payload in payloads:
        test_url = f"{url}?q={payload}"
        response = requests.get(test_url)
        if payload in response.text:
            return f"Potential XSS vulnerability found with payload: {payload}"
    return "No XSS vulnerabilities found"

def run_port_scanner():
    target = simpledialog.askstring("Port Scanner", "Enter target (e.g., example.com):")
    start_port = simpledialog.askinteger("Port Scanner", "Enter start port:")
    end_port = simpledialog.askinteger("Port Scanner", "Enter end port:")
    if target and start_port and end_port:
        result = port_scanner(target, start_port, end_port)
        messagebox.showinfo("Port Scanner Result", result)

def run_sql_injection_test():
    url = simpledialog.askstring("SQL Injection Test", "Enter URL to test for SQL Injection:")
    if url:
        result = check_sql_injection(url)
        messagebox.showinfo("SQL Injection Test Result", result)

def run_password_strength_checker():
    password = simpledialog.askstring("Password Strength Checker", "Enter password to evaluate:", show='*')
    if password:
        result = password_strength_checker(password)
        messagebox.showinfo("Password Strength Checker Result", f"Strength: {result['strength']}\nFindings:\n" + "\n".join(result['findings']))

def run_xss_scanner():
    url = simpledialog.askstring("XSS Scanner", "Enter URL to test for XSS:")
    if url:
        result = xss_scanner(url)
        messagebox.showinfo("XSS Scanner Result", result)

def create_gui():
    root = tk.Tk()
    root.title("Security Suite Tools")
    root.geometry('320x340')
    root.configure(bg='#4e1275')
    tk.Label(root, text="Security Suite Tools", bg='#4e1275', fg='white', font=("Helvetica", 20, "bold")).pack(pady=10)
    tk.Frame(root, height=2, bd=1, relief=tk.SUNKEN, bg='white').pack(fill=tk.X, padx=5, pady=10)
    tk.Label(root, text="Choose a tool to run:", bg='#4e1275', fg='white', font=("Helvetica", 12)).pack(pady=5)
    tk.Button(root, text="Port Scanner", command=run_port_scanner).pack(pady=10)
    tk.Button(root, text="SQL Injection Test", command=run_sql_injection_test).pack(pady=10)
    tk.Button(root, text="Password Strength Checker", command=run_password_strength_checker).pack(pady=10)
    tk.Button(root, text="XSS Scanner", command=run_xss_scanner).pack(pady=10)
    tk.Button(root, text="Exit", command=root.quit).pack(pady=10)
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
