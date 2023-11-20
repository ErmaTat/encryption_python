from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# create the keys
def key_pair():
    private_key=rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key=private_key.public_key()
    return private_key, public_key

# encrypt message
def encrypt(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# decrypt with private key
def decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()


private_key, public_key = key_pair()

message = input("Enter message to encryt: ")
ciphertext = encrypt(message, public_key)
decrypted_message = decrypt(ciphertext, private_key)
print(f"Encrypted message: {ciphertext}")
print(f"Decrypted message: {decrypted_message}")
