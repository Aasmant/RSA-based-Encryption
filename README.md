# 🔐 RSA-Based Encryption System 

This project implements the **RSA (Rivest–Shamir–Adleman) algorithm**, a widely used public-key cryptographic system for secure data transmission. It allows users to generate keys, encrypt messages, and decrypt ciphertext using Python.

## 🚀 Features

* 🔑 RSA key pair generation (Public & Private keys)
* 🔒 Encrypt plaintext messages
* 🔓 Decrypt ciphertext back to original message
* 📏 Customizable key size (for security level)
* ⚡ Lightweight implementation using core Python

## 🛠️ Technologies Used

* Python 3
* Built-in modules:

  * `random`
  * `math`

## 📦 Project Structure

```
rsa-based-encryption/
│── rsa.py                # Core RSA algorithm implementation
│── key_generation.py     # Handles key creation
│── encrypt.py            # Encryption logic
│── decrypt.py            # Decryption logic
│── main.py               # Entry point / demo usage
```

*(Note: Adjust filenames if your repo structure is different.)*

## ⚙️ Installation & Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/rsa-based-encryption.git
   cd rsa-based-encryption
   ```

2. Run the project:

   ```bash
   python main.py
   ```

## 🧪 Usage

### 1️⃣ Generate Keys

* Run the key generation script or function
* It will produce:

  * Public Key `(e, n)`
  * Private Key `(d, n)`

### 2️⃣ Encrypt Message

```python
ciphertext = encrypt(message, public_key)
```

### 3️⃣ Decrypt Message

```python
plaintext = decrypt(ciphertext, private_key)
```

## 📌 Example

```python
message = "Hello World"

public_key, private_key = generate_keys()

encrypted = encrypt(message, public_key)
print("Encrypted:", encrypted)

decrypted = decrypt(encrypted, private_key)
print("Decrypted:", decrypted)
```

## 🔍 How It Works

1. Generate two large prime numbers `p` and `q`
2. Compute:

   * `n = p * q`
   * `φ(n) = (p-1)(q-1)`
3. Choose public exponent `e`
4. Compute private key `d` such that:

   ```
   d ≡ e⁻¹ mod φ(n)
   ```
5. Encryption:

   ```
   C = M^e mod n
   ```
6. Decryption:

   ```
   M = C^d mod n
   ```

## ⚠️ Disclaimer

* This implementation is for **educational purposes only**
* Not secure for real-world production use
* Does not include padding schemes like OAEP

## 📄 License

This project is open-source and free to use.
