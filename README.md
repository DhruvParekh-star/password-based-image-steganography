---

# 🔐 Password-Based Image Steganography using Python

A cybersecurity-focused Python project that securely **encrypts and hides secret text inside images** using **password-based encryption** and **Least Significant Bit (LSB) steganography**, implemented with a **Graphical User Interface (GUI)**.


---

## 📖 Project Overview

In today’s digital world, secure communication is critical. While encryption protects data from unauthorized access, it does not conceal the existence of the data itself. This project enhances security by combining **cryptography** and **steganography** to ensure both **confidentiality** and **concealment** of sensitive information.

The application encrypts a secret message using a user-defined password and embeds it into an image using LSB steganography. The resulting image looks visually unchanged, making the hidden communication difficult to detect.

---

## 🎯 Problem Statement

Traditional encryption techniques secure the content of data but fail to hide its presence. Encrypted data can still attract attackers. There is a need for a system that not only encrypts sensitive information but also hides it within another medium to provide an additional layer of security.

---

## 🧠 Project Description

This project implements a **password-based image steganography system** using Python.
The workflow is as follows:

1. The user selects an image using the GUI.
2. The user enters a secret message and a password.
3. The message is encrypted using a XOR-based encryption algorithm.
4. The encrypted message is hidden inside the image using the Least Significant Bit (LSB) technique.
5. For decryption, the user selects the encrypted image and enters the correct password.
6. The hidden message is extracted and decrypted only if the correct password is provided.

---

## 🎯 Objectives

* To implement secure data hiding using steganography
* To encrypt sensitive information using a password
* To build a user-friendly GUI-based application
* To demonstrate practical cybersecurity concepts

---

## 👥 End Users

* Cybersecurity students
* Python learners and developers
* Educational institutions
* Individuals sharing confidential information
* Researchers exploring information security

---

## 🛠️ Technologies Used

### Programming Language

* Python

### Libraries

* OpenCV – image processing
* NumPy – pixel manipulation
* Tkinter – graphical user interface

### Concepts

* Steganography (LSB method)
* Encryption & Decryption
* Secure data hiding

---

## 🧩 System Architecture

```
User Input (Message + Password)
            ↓
      Encryption (XOR)
            ↓
    LSB Steganography
            ↓
      Encrypted Image
            ↓
   Password-Based Decryption
```

---

## ⚙️ Features

* 🔑 Password-based encryption and decryption
* 🖼️ Image-based data hiding using LSB technique
* 🧑‍💻 Graphical User Interface (GUI)
* 📂 Image selection using file dialog
* 🔐 Secure access (wrong password → unreadable data)
* 📁 Supports PNG and JPG images
* 🎓 Suitable for academic and cybersecurity projects

---

## 📦 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/DhruvParekh-star/password-based-image-steganography.git
cd password-based-image-steganography
```

### Step 2: Install Required Libraries

```bash
pip install opencv-python numpy
```

---

## ▶️ How to Run

```bash
python steganography_gui.py
```

---

## 🧪 Usage

### 🔒 Encryption

1. Launch the application
2. Click **Select Image**
3. Enter the secret message
4. Enter a password
5. Click **Encrypt & Hide**
6. Encrypted image is saved

### 🔓 Decryption

1. Select the encrypted image
2. Enter the correct password
3. Click **Decrypt Message**
4. Hidden message is displayed

---

## 📊 Results

* Secret messages are successfully hidden inside images
* No visible distortion in the encrypted image
* Password-protected secure communication
* Simple and intuitive user interface

---

## 🚀 Future Scope

* Implement AES encryption for stronger security
* Hide files (PDF, TXT, DOC) instead of text only
* Add user authentication system
* Improve GUI with modern themes
* Develop a mobile application version

---


## 📜 License

This project is licensed under the **MIT License**.

---

## 🙏 Acknowledgment

This project was developed as a **cybersecurity mini project** for academic and educational purposes.

---

## ⭐ Support

If you find this project useful, please ⭐ star the repository and share it with others.

---
