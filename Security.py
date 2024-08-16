import tkinter as tk
from tkinter import ttk, filedialog, Canvas, colorchooser
import rsa
import random

public_key = None
private_key = None
encryption_key = None
modified_color_code = None  # Variable to store the modified color code

# Function to check if a number is an Armstrong number
def is_armstrong_number(num):
    digits = list(map(int, str(num)))
    power = len(digits)
    return num == sum(d ** power for d in digits)

# Function to generate a random Armstrong number within a given range
def generate_random_armstrong():
    armstrong_numbers = [num for num in range(100, 10000) if is_armstrong_number(num)]
    return random.choice(armstrong_numbers)

# Generate a random Armstrong number and store it in ARMSTRONG_NUMBER
ARMSTRONG_NUMBER = generate_random_armstrong()

# Function to generate RSA key pair
def generate_key_pair():
    global public_key, private_key
    public_key, private_key = rsa.newkeys(2048)  # Change key size here
    
    # Extract numerical components of the keys and truncate to 2 digits
    public_key_n = str(public_key.n)[:4]
    public_key_e = str(public_key.e)[:4]
    private_key_n = str(private_key.n)[:4]
    private_key_d = str(private_key.d)[:4]
    
    # Update entry fields with the full numerical keys
    entry_public_key.delete(0, tk.END)
    entry_public_key.insert(0, f"n: {public_key_n}, e: {public_key_e}")
    entry_private_key.delete(0, tk.END)
    entry_private_key.insert(0, f"n: {private_key_n}, d: {private_key_d}")

# Function to set encryption key for color modification
def add_encryption_key():
    global encryption_key
    try:
        key = int(entry_key.get())
        encryption_key = key
        label_result.config(text="Encryption Key Added")
    except ValueError:
        encryption_key = None
        label_result.config(text="Invalid Encryption Key")

# Function to modify color based on encryption key
def modify_color():
    global encryption_key, modified_color_code
    try:
        color = entry_color.get()
        rgb_values = tuple(map(int, color.split(',')))
        modified_color = tuple((rgb_values[i] + encryption_key) % 256 for i in range(3))
        modified_color_code = modified_color
        label_result.config(text=f"Modified Color: {modified_color}")
        root.configure(bg='#%02x%02x%02x' % modified_color)
        canvas_color.delete("color_rect")
        canvas_color.create_rectangle(5, 5, 50, 50, fill='#%02x%02x%02x' % modified_color, outline="black", tags="color_rect")
    except (ValueError, TypeError):
        label_result.config(text="Invalid Color or Key")

# Function to validate the modified color code
def validate_modified_color(color):
    try:
        rgb_values = tuple(map(int, color.split(',')))
        return len(rgb_values) == 3 and all(0 <= val <= 255 for val in rgb_values)
    except ValueError:
        return False

# Function to encrypt plain text
def encrypt_text():
    try:
        plain_text = entry_plain_text.get()
        encrypted_text = ''.join([str(ord(char) + ARMSTRONG_NUMBER).zfill(3) for char in plain_text])
        encrypted_text = rsa.encrypt(encrypted_text.encode(), public_key).hex()
        entry_cipher_text.delete(0, tk.END)
        entry_cipher_text.insert(tk.END, encrypted_text)
    except (ValueError, TypeError, rsa.pkcs1.EncryptionError):
        entry_cipher_text.delete(0, tk.END)
        entry_cipher_text.insert(tk.END, "Encryption Failed")

# Function to save cipher text to a file
def save_cipher_text():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        cipher_text = entry_cipher_text.get()
        with open(file_path, "w") as file:
            file.write(cipher_text)

# Function to decrypt cipher text
def decrypt_text():
    try:
        stored_color_code = modified_color_code
        entered_color_code = entry_modified_color.get()

        if not validate_modified_color(entered_color_code):
            label_decryption_result.config(text="Invalid Color Code")
            entry_decrypted_text.delete(0, tk.END)
            return

        entered_rgb = tuple(map(int, entered_color_code.split(',')))
        if stored_color_code != entered_rgb:
            label_decryption_result.config(text="Incorrect Color Code")
            entry_decrypted_text.delete(0, tk.END)
            return

        cipher_text = entry_cipher_text_dec.get()
        decrypted_text = rsa.decrypt(bytes.fromhex(cipher_text), private_key).decode()
        plain_text = ''.join([chr(int(decrypted_text[i:i+3]) - ARMSTRONG_NUMBER) for i in range(0, len(decrypted_text), 3)])
        entry_decrypted_text.delete(0, tk.END)
        entry_decrypted_text.insert(tk.END, plain_text)
        label_decryption_result.config(text="Decryption Successful")
    except (ValueError, TypeError, rsa.pkcs1.DecryptionError):
        label_decryption_result.config(text="Decryption Failed")
        entry_decrypted_text.delete(0, tk.END)

# Function to browse and select cipher text file for decryption
def browse_cipher_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "r") as file:
            cipher_text = file.read()
        entry_cipher_text_dec.delete(0, tk.END)
        entry_cipher_text_dec.insert(tk.END, cipher_text)

# Function to open color picker dialog and insert chosen color into entry_color
def open_color_picker():
    color_code = colorchooser.askcolor(title="Choose color")
    if color_code:
        r, g, b = color_code[0]
        entry_color.delete(0, tk.END)
        entry_color.insert(tk.END, f"{int(r)},{int(g)},{int(b)}")

# Main Tkinter window
root = tk.Tk()
root.title("RSA Encryption & Text Encryption")
root.geometry("800x600")  # Set window size
root.configure(bg="white")  # Set background color to white

# Create a Notebook (tabbed interface)
style = ttk.Style()
style.configure('TNotebook.Tab', font=('Times New Roman', 16), padding=(10, 10))  # Increase tab font size and padding

notebook = ttk.Notebook(root, style='TNotebook')
notebook.pack(fill='both', expand=True)

def add_scrollable_frame(notebook, tab_name):
    frame = ttk.Frame(notebook)
    canvas = Canvas(frame)
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    notebook.add(frame, text=tab_name)
    return scrollable_frame

# Add scrollable frames for encryption and decryption tabs
frame_encrypt = add_scrollable_frame(notebook, 'Encryption')
frame_decrypt = add_scrollable_frame(notebook, 'Decryption')

# Encryption tab content
label_generate_key_pair = tk.Label(frame_encrypt, text="Generate Key Pair (RSA)", font=("Times New Roman", 20))
label_generate_key_pair.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

btn_generate_key_pair = tk.Button(frame_encrypt, text="Generate", command=generate_key_pair, font=("Times New Roman", 18), bg="lightblue")
btn_generate_key_pair.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

label_public_key = tk.Label(frame_encrypt, text="Public Key:", font=("Times New Roman", 16))
label_public_key.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky='ew')
entry_public_key = tk.Entry(frame_encrypt, width=100, font=("Times New Roman", 16))
entry_public_key.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

label_private_key = tk.Label(frame_encrypt, text="Private Key:", font=("Times New Roman", 16))
label_private_key.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky='ew')
entry_private_key = tk.Entry(frame_encrypt, width=100, font=("Times New Roman", 16))
entry_private_key.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

label_key = tk.Label(frame_encrypt, text="Encryption Key:", font=("Times New Roman", 16))
label_key.grid(row=6, column=0, padx=10, pady=10, sticky='e')
entry_key = tk.Entry(frame_encrypt, font=("Times New Roman", 16))
entry_key.grid(row=6, column=1, padx=10, pady=10, sticky='w')

btn_add_key = tk.Button(frame_encrypt, text="Add Key", command=add_encryption_key, font=("Times New Roman", 16), bg="lightgreen")
btn_add_key.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

label_color = tk.Label(frame_encrypt, text="Color (R,G,B):", font=("Times New Roman", 16))
label_color.grid(row=8, column=0, padx=10, pady=10, sticky='e')
entry_color = tk.Entry(frame_encrypt, font=("Times New Roman", 16))
entry_color.grid(row=8, column=1, padx=10, pady=10, sticky='w')

btn_color_picker = tk.Button(frame_encrypt, text="Pick Color", command=open_color_picker, font=("Times New Roman", 16), bg="lightyellow")
btn_color_picker.grid(row=9, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

btn_modify_color = tk.Button(frame_encrypt, text="Modify Color", command=modify_color, font=("Times New Roman", 16), bg="lightcoral")
btn_modify_color.grid(row=10, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

label_result = tk.Label(frame_encrypt, text="", font=("Times New Roman", 16))
label_result.grid(row=11, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

canvas_color = Canvas(frame_encrypt, width=60, height=60)
canvas_color.grid(row=12, column=0, columnspan=2, padx=10, pady=10)

label_plain_text = tk.Label(frame_encrypt, text="Plain Text:", font=("Times New Roman", 16))
label_plain_text.grid(row=13, column=0, padx=10, pady=10, sticky='e')
entry_plain_text = tk.Entry(frame_encrypt, width=70, font=("Times New Roman", 16))
entry_plain_text.grid(row=13, column=1, padx=10, pady=10, sticky='w')

btn_encrypt = tk.Button(frame_encrypt, text="Encrypt", command=encrypt_text, font=("Times New Roman", 16), bg="lightblue")
btn_encrypt.grid(row=14, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

label_cipher_text = tk.Label(frame_encrypt, text="Cipher Text:", font=("Times New Roman", 16))
label_cipher_text.grid(row=15, column=0, padx=10, pady=10, sticky='e')
entry_cipher_text = tk.Entry(frame_encrypt, width=70, font=("Times New Roman", 16))
entry_cipher_text.grid(row=15, column=1, padx=10, pady=10, sticky='w')

btn_save_cipher = tk.Button(frame_encrypt, text="Save Cipher Text", command=save_cipher_text, font=("Times New Roman", 16), bg="lightgreen")
btn_save_cipher.grid(row=16, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

# Decryption tab content
label_cipher_text_dec = tk.Label(frame_decrypt, text="Cipher Text:", font=("Times New Roman", 16))
label_cipher_text_dec.grid(row=0, column=0, padx=10, pady=10, sticky='e')
entry_cipher_text_dec = tk.Entry(frame_decrypt, width=70, font=("Times New Roman", 16))
entry_cipher_text_dec.grid(row=0, column=1, padx=10, pady=10, sticky='w')

btn_browse_cipher = tk.Button(frame_decrypt, text="Browse", command=browse_cipher_file, font=("Times New Roman", 16), bg="lightblue")
btn_browse_cipher.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

label_modified_color = tk.Label(frame_decrypt, text="Modified Color Code (R,G,B):", font=("Times New Roman", 16))
label_modified_color.grid(row=2, column=0, padx=10, pady=10, sticky='e')
entry_modified_color = tk.Entry(frame_decrypt, font=("Times New Roman", 16))
entry_modified_color.grid(row=2, column=1, padx=10, pady=10, sticky='w')
entry_modified_color.bind("<KeyRelease>", lambda event: update_color_display_dec())

def update_color_display_dec():
    entered_color = entry_modified_color.get()
    try:
        rgb_values = tuple(map(int, entered_color.split(',')))
        if len(rgb_values) == 3:
            canvas_color_dec.create_rectangle(5, 5, 50, 50, fill='#%02x%02x%02x' % tuple(rgb_values), outline="black", tags="color_rect_dec")
    except ValueError:
        pass

canvas_color_dec = Canvas(frame_decrypt, width=60, height=60)
canvas_color_dec.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

btn_decrypt = tk.Button(frame_decrypt, text="Decrypt", command=decrypt_text, font=("Times New Roman", 16), bg="lightgreen")
btn_decrypt.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

label_decrypted_text = tk.Label(frame_decrypt, text="Decrypted Text:", font=("Times New Roman", 16))
label_decrypted_text.grid(row=5, column=0, padx=10, pady=10, sticky='e')
entry_decrypted_text = tk.Entry(frame_decrypt, width=70, font=("Times New Roman", 16))
entry_decrypted_text.grid(row=5, column=1, padx=10, pady=10, sticky='w')

label_decryption_result = tk.Label(frame_decrypt, text="", font=("Times New Roman", 16))
label_decryption_result.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky='ew')

# Start Tkinter event loop
root.mainloop()