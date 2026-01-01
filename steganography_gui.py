import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox

# ---------------- Encryption / Decryption ----------------
def xor_encrypt_decrypt(text, password):
    result = ""
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ ord(password[i % len(password)]))
    return result


def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)


def binary_to_text(binary):
    chars = [binary[i:i+8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(c, 2)) for c in chars)


# ---------------- Steganography Logic ----------------
def embed_message(image_path, message, password, output_path):
    img = cv2.imread(image_path)
    if img is None:
        raise Exception("Image not found")

    encrypted = xor_encrypt_decrypt(message, password)
    binary_msg = text_to_binary(encrypted) + "1111111111111110"

    flat_img = img.flatten()

    if len(binary_msg) > len(flat_img):
        raise Exception("Message too large for image")

    for i in range(len(binary_msg)):
        flat_img[i] = (flat_img[i] & 254) | int(binary_msg[i])

    encoded_img = flat_img.reshape(img.shape)
    cv2.imwrite(output_path, encoded_img)


def extract_message(image_path, password):
    img = cv2.imread(image_path)
    if img is None:
        raise Exception("Image not found")

    flat_img = img.flatten()
    binary_data = ""

    for pixel in flat_img:
        binary_data += str(pixel & 1)
        if binary_data.endswith("1111111111111110"):
            break

    binary_data = binary_data[:-16]
    encrypted = binary_to_text(binary_data)
    return xor_encrypt_decrypt(encrypted, password)


# ---------------- GUI Functions ----------------
selected_image = ""


def select_image():
    global selected_image
    selected_image = filedialog.askopenfilename(
        filetypes=[("Image Files", "*.png *.jpg *.jpeg")]
    )
    if selected_image:
        image_label.config(text=selected_image)


def encrypt_action():
    if not selected_image:
        messagebox.showerror("Error", "Select an image first")
        return

    msg = message_entry.get("1.0", tk.END).strip()
    pwd = password_entry.get()

    if not msg or not pwd:
        messagebox.showerror("Error", "Message and password required")
        return

    output = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG Image", "*.png")]
    )

    try:
        embed_message(selected_image, msg, pwd, output)
        messagebox.showinfo("Success", "Message encrypted & hidden successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def decrypt_action():
    if not selected_image:
        messagebox.showerror("Error", "Select encrypted image")
        return

    pwd = password_entry.get()
    if not pwd:
        messagebox.showerror("Error", "Password required")
        return

    try:
        msg = extract_message(selected_image, pwd)
        messagebox.showinfo("Decrypted Message", msg)
    except Exception as e:
        messagebox.showerror("Error", str(e))


# ---------------- GUI Layout ----------------
root = tk.Tk()
root.title("Steganography Tool")
root.geometry("500x450")
root.resizable(False, False)

tk.Label(root, text="Image Steganography", font=("Arial", 16, "bold")).pack(pady=10)

tk.Button(root, text="Select Image", command=select_image).pack()
image_label = tk.Label(root, text="No image selected", wraplength=450)
image_label.pack(pady=5)

tk.Label(root, text="Secret Message").pack()
message_entry = tk.Text(root, height=5, width=55)
message_entry.pack()

tk.Label(root, text="Password").pack(pady=5)
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack()

tk.Button(root, text="Encrypt & Hide", command=encrypt_action, bg="#4CAF50", fg="white").pack(pady=10)
tk.Button(root, text="Decrypt Message", command=decrypt_action, bg="#2196F3", fg="white").pack()

tk.Label(root, text="Cybersecurity Mini Project", fg="gray").pack(side="bottom", pady=10)

root.mainloop()
