import os, uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def checkForKey(file_name='rsa2048.pem'):
    """
    Check if the private key file exists.
    """
    return os.path.exists(file_name)

def generateKey(file_name='rsa2048.pem'):
    """
    Generate a new RSA private key and save it to a file.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(file_name, 'wb') as priv_data_file:
        priv_data_file.write(private_pem)
    print(f"Private key saved to {file_name}")
    return private_key

def loadPrivateKey(file_name='rsa2048.pem'):
    """
    Load the RSA private key from a file.
    """
    with open(file_name, 'rb') as priv_key_file:
        return serialization.load_pem_private_key(
            priv_key_file.read(),
            password=None
        )
    
def getPublicKey(private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    """
    Generate the public key from a given private key.

    Args:
        private_key (rsa.RSAPrivateKey): The private key object.

    Returns:
        rsa.RSAPublicKey: The corresponding public key object.
    """
    return private_key.public_key()

def serializePublicKey(public_key: rsa.RSAPublicKey) -> str:
    """
    Serialize a public key to PEM format.

    Args:
        public_key (rsa.RSAPublicKey): The public key to serialize.

    Returns:
        str: The serialized public key in PEM format as a string.
    """
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem.decode('utf-8')

def generateSalt(size: int):
    """
    Generates a salt of wanted size.
    """
    return (os.urandom(size)).hex()

def generateUUID() -> str:
    """
    Generates a UUID.
    """
    return str(uuid.uuid4())

def encrypt(data: str, publicKey) -> bytes:
    """
    Encrypts data with MGF1 and SHA256, no label.
    """
    return publicKey.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt(data: str, privateKey) -> bytes:
    """
    Decrypts data with MGF1 and SHA256, no label.
    """
    return privateKey.decrypt(
        bytes.fromhex(data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )