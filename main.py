import streamlit as st
from aes_cipher import encrypt_text, decrypt_text, encrypt_file, decrypt_file

st.title("AES Encryption & Decryption App")

# Key Input Section
encryption_key = st.text_input("Enter a 16, 24, or 32-byte encryption key:", type="password")
if len(encryption_key) not in [16, 24, 32]:
    st.warning("Key must be either 16, 24, or 32 bytes long.")
    encryption_key_bytes = None  # Key is invalid, so we don't use it
else:
    encryption_key_bytes = encryption_key.encode()

# Mode Selector
mode = st.selectbox("Choose an operation:", ["Encrypt", "Decrypt"])

# Type Selector
type_selector = st.selectbox("Select type:", ["Text", "File"])

# Text Encryption/Decryption
if type_selector == "Text" and encryption_key_bytes:
    if mode == "Encrypt":
        plaintext = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt Text"):
            if plaintext:
                encrypted_text = encrypt_text(encryption_key_bytes, plaintext)
                st.success(f"Encrypted text: {encrypted_text}")
            else:
                st.error("Please enter text to encrypt.")
                
    elif mode == "Decrypt":
        encrypted_text = st.text_area("Enter text to decrypt:")
        if st.button("Decrypt Text"):
            if encrypted_text:
                try:
                    decrypted_text = decrypt_text(encryption_key_bytes, encrypted_text)
                    st.success(f"Decrypted text: {decrypted_text}")
                except Exception as e:
                    st.error("Decryption failed. Please check the encrypted text and key.")
            else:
                st.error("Please enter text to decrypt.")

# File Encryption/Decryption
elif type_selector == "File" and encryption_key_bytes:
    file = st.file_uploader("Upload a file")
    if file is not None:
        file_data = file.read()
        
        if mode == "Encrypt":
            if st.button("Encrypt File"):
                encrypted_file_data = encrypt_file(encryption_key_bytes, file_data)
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_file_data,
                    file_name="encrypted_file.aes"
                )
                st.success("File encrypted successfully.")

        elif mode == "Decrypt":
            if st.button("Decrypt File"):
                try:
                    decrypted_file_data = decrypt_file(encryption_key_bytes, file_data)
                    st.download_button(
                        label="Download Decrypted File",
                        data=decrypted_file_data,
                        file_name="decrypted_file"
                    )
                    st.success("File decrypted successfully.")
                except Exception as e:
                    st.error("Decryption failed. Please check the file and key.")
else:
    if encryption_key_bytes is None:
        st.info("Please enter a valid encryption key to proceed.")
