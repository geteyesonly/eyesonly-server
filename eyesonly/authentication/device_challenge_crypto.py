
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl.secret import SecretBox
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
from nacl.utils import random as nacl_random


DEFAULT_KEY_WRAP_ALGORITHM = 'x25519-hkdf-xchacha20poly1305'
DEVICE_CHALLENGE_ENCRYPTION_ALGORITHM = DEFAULT_KEY_WRAP_ALGORITHM
DEVICE_CHALLENGE_HKDF_INFO = b'eyesonly-device-auth-challenge-v1'


def encrypt_device_auth_challenge(*, challenge_value, public_key, public_key_algorithm):
    if public_key_algorithm != 'x25519':
        raise ValueError('Unsupported device authentication key algorithm.')

    try:
        recipient_public_key = x25519.X25519PublicKey.from_public_bytes(
            base64.b64decode(public_key, validate=True),
        )
    except Exception as exc:
        raise ValueError('Invalid x25519 public key encoding.') from exc

    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=DEVICE_CHALLENGE_HKDF_INFO,
    ).derive(shared_secret)

    nonce = nacl_random(24)

    # PyNaCl expects bytes for key, nonce, and message
    ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
        challenge_value.encode('utf-8'),
        aad=None,
        nonce=nonce,
        key=derived_key,
    )

    ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return {
        'algorithm': DEVICE_CHALLENGE_ENCRYPTION_ALGORITHM,
        'ephemeral_public_key': base64.b64encode(ephemeral_public_key).decode('ascii'),
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
    }


def generate_decoy_device_auth_challenge():
    nonce = os.urandom(24)
    # Ensure base64 encoding produces 32 characters for a 24-byte nonce
    nonce_b64 = base64.b64encode(nonce).decode('ascii')
    assert len(base64.b64decode(nonce_b64)) == 24, f"Nonce is not 24 bytes: {len(base64.b64decode(nonce_b64))}"
    return {
        'algorithm': DEVICE_CHALLENGE_ENCRYPTION_ALGORITHM,
        'ephemeral_public_key': base64.b64encode(os.urandom(32)).decode('ascii'),
        'nonce': nonce_b64,
        'ciphertext': base64.b64encode(os.urandom(48)).decode('ascii'),
    }