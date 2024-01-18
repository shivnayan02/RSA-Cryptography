from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Function to generate a key pair (private key and corresponding public key)
def generate_key_pair():
    # Generate a private key using RSA algorithm
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Extract the public key from the private key
    public_key = private_key.public_key()
    return private_key, public_key

# Function to sign a message using a private key
def sign_message(message, private_key):
    # Sign the message using PSS (Probabilistic Signature Scheme) with SHA-256 hashing
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Function to verify the signature of a message using a public key
def verify_signature(message, signature, public_key):
    try:
        # Verify the signature using PSS with SHA-256 hashing
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        # If verification fails, print an error message
        print(f"Signature verification failed: {e}")
        return False

# Function to encrypt a file using a public key
def encrypt_file(file_path, public_key):
    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Encrypt the plaintext using OAEP (Optimal Asymmetric Encryption Padding) with SHA-256 hashing
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ci
