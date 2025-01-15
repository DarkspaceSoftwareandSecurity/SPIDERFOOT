import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import socket
import subprocess
from cryptography.fernet import Fernet

# Configuration
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

# XDR Capability Function
def xdr_analysis():
    target_ip = entry_ip.get()
    if not target_ip:
        messagebox.showwarning("XDR Analysis", "Please enter a target IP address.")
        return
    
    # Simulated XDR Analysis (Replace with real implementation)
    result_message = f"Performing XDR analysis on {target_ip}...\n" \
                     "Analyzing network traffic, endpoint behaviors, and server logs...\n" \
                     "XDR analysis is in progress. Results will be displayed shortly."
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, result_message)

# Port Scanner Function
def scan_ports():
    target_ip = entry_ip.get()
    if not target_ip:
        messagebox.showwarning("Port Scan", "Please enter a target IP address.")
        return

    open_ports = []
    common_ports = [21, 22, 23, 25, 80, 110, 443, 8080]

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    if open_ports:
        result_message = f"Open Ports on {target_ip}: {', '.join(map(str, open_ports))}"
    else:
        result_message = f"No common ports open on {target_ip}"

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, result_message)

# File Encryption Function
def encrypt_file():
    file_path = entry_file_path.get()
    if not file_path:
        file_path = filedialog.askopenfilename()

    if not file_path:
        return

    with open(file_path, 'rb') as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"File encrypted and saved as {encrypted_file_path}")

# File Decryption Function
def decrypt_file():
    file_path = entry_file_path.get()
    if not file_path:
        file_path = filedialog.askopenfilename()

    if not file_path or not file_path.endswith('.encrypted'):
        messagebox.showwarning("File Decryption", "Please select a valid encrypted file.")
        return

    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Failed to decrypt the file. Incorrect key?")
        return

    decrypted_file_path = file_path.replace('.encrypted', '')
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"File decrypted and saved as {decrypted_file_path}")

# RCE Function
def remote_code_execution():
    target_ip = entry_ip.get()
    command = entry_command.get()
    if not target_ip or not command:
        messagebox.showwarning("RCE", "Please enter both target IP address and command.")
        return

    # Simulated RCE (Replace with actual remote execution logic)
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        result_message = f"Command output:\n{result.stdout}\nErrors (if any):\n{result.stderr}"
    except Exception as e:
        result_message = f"Failed to execute command: {e}"

    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, result_message)

# Initialize Tkinter GUI
app = tk.Tk()
app.title("Ethical Hacking Educational Tool")

# Set the background color to black
app.configure(bg='black')

# Add the creator's name
tk.Label(app, text="Darkspace Software & Security", bg="black", fg="lime", font=("Helvetica", 14)).pack(pady=10)

# IP Address Section
tk.Label(app, text="Target IP Address:", bg='black', fg='lime').pack(pady=5)
entry_ip = tk.Entry(app, bg='black', fg='lime', insertbackground='lime')
entry_ip.pack(pady=5)

# Command Section for RCE
tk.Label(app, text="Command for RCE:", bg='black', fg='lime').pack(pady=5)
entry_command = tk.Entry(app, bg='black', fg='lime', insertbackground='lime')
entry_command.pack(pady=5)

# File Path Section
tk.Label(app, text="File Path (Optional):", bg='black', fg='lime').pack(pady=5)
entry_file_path = tk.Entry(app, bg='black', fg='lime', insertbackground='lime')
entry_file_path.pack(pady=5)

# Button Layout
button_frame = tk.Frame(app, bg='black')
button_frame.pack(pady=10)

# Buttons in Columns
column1 = tk.Frame(button_frame, bg='black')
column1.pack(side=tk.LEFT, padx=10)

column2 = tk.Frame(button_frame, bg='black')
column2.pack(side=tk.LEFT, padx=10)

tk.Button(column1, text="Scan Ports", command=scan_ports, bg='lime', fg='black', activebackground='darkgreen').pack(pady=5)
tk.Button(column1, text="Encrypt File", command=encrypt_file, bg='lime', fg='black', activebackground='darkgreen').pack(pady=5)
tk.Button(column1, text="Decrypt File", command=decrypt_file, bg='lime', fg='black', activebackground='darkgreen').pack(pady=5)

tk.Button(column2, text="XDR Analysis", command=xdr_analysis, bg='lime', fg='black', activebackground='darkgreen').pack(pady=5)
tk.Button(column2, text="Execute Command (RCE)", command=remote_code_execution, bg='lime', fg='black', activebackground='darkgreen').pack(pady=5)

# Output Text Box
output_text = scrolledtext.ScrolledText(app, width=60, height=15, bg='black', fg='lime', insertbackground='lime')
output_text.pack(pady=20)

# Run the GUI loop
app.mainloop()
