import tkinter as tk
from tkinter import ttk
from salsa20 import XSalsa20_xor
import base64
from os import urandom
from ecc.curve import secp256k1
from ecc.key import gen_keypair
from ecc.cipher import ElGamal
import binascii
import schnorr
import datetime

# Configure the root window
root = tk.Tk()
root.title("Alice and Bob Encryption/Decryption")
root.geometry("1200x800")
root.resizable(False, False)
root.configure(background="#202020")

style = ttk.Style()
style.theme_use("clam")

style.configure("TFrame", background="#202020")
style.configure(
    "TButton",
    background="#333333",
    foreground="#CCCCCC",
    font=("Arial", 10),
    borderwidth=1,
    relief="flat",
)
style.configure(
    "TLabelFrame",
    background="#202020",
    foreground="#CCCCCC",
    font=("Arial", 10),
    borderwidth=1,
)
style.configure(
    "TLabelFrame.Label", background="#202020", foreground="#CCCCCC", font=("Arial", 20)
)

text_style = {
    "background": "#333333",
    "foreground": "#CCCCCC",
    "insertbackground": "#CCCCCC",
    "borderwidth": 0,
    "font": ("Arial", 10),
}


Alice_private, Alice_public = None, None
Bob_private, Bob_public = None, None
keys_generated = False


# Function to add messages to the log window
def add_log_message(message):
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    full_message = f"{timestamp}: {message}"

    log_text.configure(state="normal")
    log_text.insert(tk.END, full_message + "\n")
    log_text.configure(state="disabled")
    log_text.see(tk.END)


def key_to_string(key):
    return hex(key)


def generate_keys():
    global Alice_private, Alice_public, Bob_private, Bob_public, keys_generated
    Alice_private, Alice_public = gen_keypair(secp256k1)
    Bob_private, Bob_public = gen_keypair(secp256k1)

    # Clear previous content and disable text editing while updating
    key_window.configure(state="normal")
    key_window.delete("1.0", tk.END)

    key_window.insert(tk.END, f"Alice's Private Key: {key_to_string(Alice_private)}\n")
    key_window.insert(
        tk.END,
        f"Alice's Public Key: ( {key_to_string(Alice_public.x)} , {key_to_string(Alice_public.y)} )\n",
    )
    key_window.insert(tk.END, f"Bob's Private Key: {key_to_string(Bob_private)}\n")
    key_window.insert(
        tk.END,
        f"Bob's Public Key: ( {key_to_string(Bob_public.x)} , {key_to_string(Bob_public.y)} )\n",
    )

    key_window.configure(state="disabled")
    add_log_message("generated keys")

    keys_generated = True  # Set the flag to True after keys are generated
    alice_send_button["state"] = "normal"  # Enable the send button for Alice
    bob_send_button["state"] = "normal"  # Enable the send button for Bob
    add_log_message("Keys have been generated.")


def Alice_send():
    if not keys_generated:
        add_log_message("Keys must be generated before sending a message.")
        return
    plaintext = (
        alice_text_area.get("end-1c linestart", "end-1c").strip().encode("utf-8")
    )
    cipher_elg = ElGamal(secp256k1)
    secret_pre = urandom(30)
    secret_suf = urandom(26)
    secret_total = secret_pre + secret_suf[:2]
    nonce = secret_suf[2:]  # like a time stamp
    ciphertext = XSalsa20_xor(plaintext, nonce, secret_total)
    add_log_message("generated ciphertext")
    sig = schnorr.schnorr.schnorr_sign(ciphertext, Alice_private)
    add_log_message("generated signature")
    Alice_point_public = (Alice_public.x, Alice_public.y)
    ciphertext_base64 = base64.b64encode(ciphertext).decode("utf-8")
    add_log_message("generated base64 ciphertext: " + ciphertext_base64)
    C1_pre, C2_pre = cipher_elg.encrypt(secret_pre, Bob_public)
    C1_suf, C2_suf = cipher_elg.encrypt(secret_suf, Bob_public)
    secret_key = [C1_pre, C2_pre, C1_suf, C2_suf]
    add_log_message("encrypted secret key")
    # send to Bob
    add_log_message("Sent to Bob")
    Bob_receive(ciphertext, sig, secret_key, Alice_point_public)
    alice_text_area.insert(tk.END, "\n")
    alice_text_area.see(tk.END)
    bob_text_area.see(tk.END)


def Bob_receive(ciphertext, sig, secret_key, Alice_point_public):

    if not schnorr.schnorr.schnorr_verify(ciphertext, Alice_point_public, sig):
        add_log_message("Invalid Signature received from Alice")
        return
    add_log_message("Signature verified")
    cipher_elg = ElGamal(secp256k1)
    C1_pre = secret_key[0]
    C2_pre = secret_key[1]
    C1_suf = secret_key[2]
    C2_suf = secret_key[3]
    decrypted_secret_pre = cipher_elg.decrypt(Bob_private, C1_pre, C2_pre)
    decrypted_secret_suf = cipher_elg.decrypt(Bob_private, C1_suf, C2_suf)
    decrypted_secret_total = decrypted_secret_pre + decrypted_secret_suf[:2]
    add_log_message("Decrypted secret key for salsa20")
    decrypted_message = XSalsa20_xor(
        ciphertext, decrypted_secret_suf[2:], decrypted_secret_total
    )
    decrypted_message_str = decrypted_message.decode("utf-8")
    add_log_message("decrypted message: " + decrypted_message_str)
    bob_text_area.insert(tk.END, "Alice: " + decrypted_message_str + "\n")


def Bob_send():
    if not keys_generated:
        add_log_message("Keys must be generated before sending a message.")
        return
    plaintext = bob_text_area.get("end-1c linestart", "end-1c").strip().encode("utf-8")
    cipher_elg = ElGamal(secp256k1)
    secret_pre = urandom(30)
    secret_suf = urandom(26)
    secret_total = secret_pre + secret_suf[:2]
    nonce = secret_suf[2:]  # like a time stamp
    ciphertext = XSalsa20_xor(plaintext, nonce, secret_total)
    add_log_message("generated ciphertext")
    sig = schnorr.schnorr.schnorr_sign(ciphertext, Bob_private)
    add_log_message("generated signature")
    Bob_point_public = (Bob_public.x, Bob_public.y)
    ciphertext_base64 = base64.b64encode(ciphertext).decode("utf-8")
    add_log_message("generated base64 ciphertext: " + ciphertext_base64)
    C1_pre, C2_pre = cipher_elg.encrypt(secret_pre, Alice_public)
    C1_suf, C2_suf = cipher_elg.encrypt(secret_suf, Alice_public)
    secret_key = [C1_pre, C2_pre, C1_suf, C2_suf]
    add_log_message("encrypted secret key")
    # send to Alice
    add_log_message("Sent to Alice")
    Alice_receive(ciphertext, sig, secret_key, Bob_point_public)
    bob_text_area.insert(tk.END, "\n")
    bob_text_area.see(tk.END)
    alice_text_area.see(tk.END)


def Alice_receive(ciphertext, sig, secret_key, Bob_point_public):

    if not schnorr.schnorr.schnorr_verify(ciphertext, Bob_point_public, sig):
        add_log_message("Invalid Signature received from Alice")
        return
    add_log_message("Signature verified")
    cipher_elg = ElGamal(secp256k1)
    C1_pre = secret_key[0]
    C2_pre = secret_key[1]
    C1_suf = secret_key[2]
    C2_suf = secret_key[3]
    decrypted_secret_pre = cipher_elg.decrypt(Alice_private, C1_pre, C2_pre)
    decrypted_secret_suf = cipher_elg.decrypt(Alice_private, C1_suf, C2_suf)
    decrypted_secret_total = decrypted_secret_pre + decrypted_secret_suf[:2]
    add_log_message("Decrypted secret key for salsa20")
    decrypted_message = XSalsa20_xor(
        ciphertext, decrypted_secret_suf[2:], decrypted_secret_total
    )
    decrypted_message_str = decrypted_message.decode("utf-8")
    add_log_message("decrypted message: " + decrypted_message_str)
    alice_text_area.insert(tk.END, "Bob: " + decrypted_message_str + "\n")


# Generate keys button frame
button_frame = ttk.Frame(root)
button_frame.pack(pady=10, fill=tk.X)

# Generate keys button
generate_keys_button = ttk.Button(
    button_frame, text="Generate Keys", command=generate_keys
)
generate_keys_button.pack(pady=5, padx=10)

# Additional frame for future extensions or additional features
key_window = ttk.Frame(root)
key_window.pack(pady=10, fill=tk.X, expand=True)

key_window = tk.Text(key_window, height=4, width=60, **text_style)
key_window.pack(padx=10, pady=7, fill=tk.X, expand=True)
key_window.configure(state="disabled")

# Frame for Alice and Bob's windows
window_frame = ttk.Frame(root)
window_frame.pack(fill=tk.BOTH, expand=True, pady=10)

# Alice's window
alice_window = ttk.LabelFrame(window_frame, text="Alice")
alice_window.pack(side=tk.LEFT, padx=10, pady=20, expand=True, fill=tk.BOTH)
alice_text_area = tk.Text(alice_window, height=10, width=60, **text_style)
alice_text_area.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
alice_send_button = ttk.Button(
    alice_window, text="Send", command=Alice_send, state="disabled"
)
alice_send_button.pack(padx=10, pady=5)


# Bob's window
bob_window = ttk.LabelFrame(window_frame, text="Bob")
bob_window.pack(side=tk.LEFT, padx=10, pady=20, expand=True, fill=tk.BOTH)
bob_text_area = tk.Text(bob_window, height=10, width=60, **text_style)
bob_text_area.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
bob_send_button = ttk.Button(
    bob_window, text="Send", command=Bob_send, state="disabled"
)
bob_send_button.pack(padx=10, pady=5)


# Log window
log_window = ttk.LabelFrame(root, text="Log")  # Creating a LabelFrame for logs
log_window.pack(
    padx=10, pady=10, fill=tk.X, expand=False
)  # Adjust padx and pady as needed

log_text = tk.Text(
    log_window, height=6, width=100, **text_style
)  # Creating a Text widget for log messages
log_text.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
log_text.configure(state="disabled")  # Making the Text widget read-only


root.mainloop()
