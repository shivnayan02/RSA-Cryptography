
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa, padding
 
def generate_key_pair():

    private_key = rsa.generate_private_key(

        public_exponent=65537,

        key_size=2048,

        backend=default_backend()

    )

    public_key = private_key.public_key()

    return private_key, public_key
 
def sign_message(message, private_key):

    signature = private_key.sign(

        message,

        padding.PSS(

            mgf=padding.MGF1(hashes.SHA256()),

            salt_length=padding.PSS.MAX_LENGTH

        ),

        hashes.SHA256()

    )

    return signature
 
def verify_signature(message, signature, public_key):

    try:

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

        print(f"Signature verification failed: {e}")

        return False
 
def encrypt_file(file_path, public_key):

    with open(file_path, 'rb') as file:

        plaintext = file.read()
 
    ciphertext = public_key.encrypt(

        plaintext,

        padding.OAEP(

            mgf=padding.MGF1(algorithm=hashes.SHA256()),

            algorithm=hashes.SHA256(),

            label=None

        )

    )
 
    return ciphertext
 
def decrypt_file(ciphertext, private_key):

    plaintext = private_key.decrypt(

        ciphertext,

        padding.OAEP(

            mgf=padding.MGF1(algorithm=hashes.SHA256()),

            algorithm=hashes.SHA256(),

            label=None

        )

    )
 
    return plaintext
 
# Generate key pairs for User 1

user1_private_key, user1_public_key = generate_key_pair()
 
# Generate key pairs for User 2

user2_private_key, user2_public_key = generate_key_pair()
 
# Example usage:

file_to_encrypt = "example.txt"
 
# User 1 signs the file

user1_signature = sign_message(file_to_encrypt.encode(), user1_private_key)
 
# User 2 verifies the signature from User 1

is_verified = verify_signature(file_to_encrypt.encode(), user1_signature, user1_public_key)

if is_verified:

    print("Signature verified successfully.")

else:

    print("Signature verification failed.")
 
# User 2 encrypts the file with User 1's public key

encrypted_data = encrypt_file(file_to_encrypt, user1_public_key)
 
# User 1 decrypts the file with their private key

decrypted_data = decrypt_file(encrypted_data, user1_private_key)
 
# Save the decrypted data to a new file

with open("decrypted_file.txt", 'wb') as decrypted_file:

    decrypted_file.write(decrypted_data)
