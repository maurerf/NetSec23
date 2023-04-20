import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def symmetric_ratchet(constant: bytes, chain_key: bytes) -> Tuple[bytes, bytes]:
    """Symmetric key ratchet
    https://signal.org/docs/specifications/doubleratchet/#symmetric-key-ratchet
    https://signal.org/docs/specifications/doubleratchet/#recommended-cryptographic-
    algorithms
    https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf
    Args:
    constant: Some constant used in the KDF
    chain_key: The chain key that is used in the KDF
    Returns:
    Tuple[bytes, bytes]: new chain_key, message_key
    """
    # derive a new key from the given previous chain key
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=constant,
    )
    new_key = hkdf.derive(chain_key)

    # derive new chain and message keys
    hkdf_msg = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"chain key",
    )
    hkdf_chain = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"message key",
    )

    return hkdf_msg.derive(new_key), hkdf_chain.derive(new_key)


def encrypt_message(message: bytes, message_key: bytes) -> bytes:
    """Encrypt the given message using the given message key
    https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    """
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(message_key), modes.CTR(iv))  # Create an AES-CTR cipher
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()  # Encrypt the message
    return iv + ciphertext  # Prepend the IV to the ciphertext


def decrypt_message(ciphertext: bytes, message_key: bytes) -> bytes:
    """Decrypt the given message using the given message key
    https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
    """
    iv = ciphertext[:16]  # Extract the IV from the ciphertext
    ciphertext = ciphertext[16:]  # Remove the IV from the ciphertext
    cipher = Cipher(algorithms.AES(message_key), modes.CTR(iv))  # Create an AES-CTR cipher
    decryptor = cipher.decryptor()
    message = decryptor.update(ciphertext) + decryptor.finalize()  # Decrypt the ciphertext
    return message


class SignalParticipant:
    def __init__(self):
        self.constant: bytes = bytes(0x0)  # todo
        initial_chain_key: bytes = bytes(0x0)  # todo
        self.current_message_key, self.current_chain_key = symmetric_ratchet(self.constant, initial_chain_key)

    def turn_ratchet(self) -> None:
        self.current_message_key, self.current_chain_key = symmetric_ratchet(self.constant, self.current_chain_key)


alice: SignalParticipant = SignalParticipant()
print("Initiated Alice: constant = " + str(alice.constant) + ", initial chain key = " + str(alice.current_chain_key))
bob: SignalParticipant = SignalParticipant()
print("Initiated Bob: constant = " + str(bob.constant) + ", initial chain key = " + str(bob.current_chain_key))

alice_message1: bytes = b"Cleartext Alice One"
alice_message2: bytes = b"Cleartext Alice One Plus One"
bob_message1: bytes = b"Cleartext Bob Succ(Zero)"
bob_message2: bytes = b"Cleartext Bob 2!"

# Alice Message 1
encr: bytes = encrypt_message(alice_message1, alice.current_message_key)
decr: bytes = decrypt_message(encr, alice.current_message_key)
print("Alice: Encrypted message: " + str(encr) + ", decrypted message: " + str(decr))
alice.turn_ratchet()
print("Alice: Ratchet turned. New chain key: " + str(alice.current_chain_key) + ", new message key: " + str(
    alice.current_message_key))

# Alice Message 2
encr: bytes = encrypt_message(alice_message2, alice.current_message_key)
decr: bytes = decrypt_message(encr, alice.current_message_key)
print("Alice: Encrypted message: " + str(encr) + ", decrypted message: " + str(decr))
alice.turn_ratchet()
print("Alice: Ratchet turned. New chain key: " + str(alice.current_chain_key) + ", new message key: " + str(
    alice.current_message_key))

# Bob Message 1
encr: bytes = encrypt_message(bob_message1, bob.current_message_key)
decr: bytes = decrypt_message(encr, bob.current_message_key)
print("Bob: Encrypted message: " + str(encr) + ", decrypted message: " + str(decr))
bob.turn_ratchet()
print("Bob: Ratchet turned. New chain key: " + str(bob.current_chain_key) + ", new message key: " + str(
    bob.current_message_key))

# Bob Message 2
encr: bytes = encrypt_message(bob_message2, bob.current_message_key)
decr: bytes = decrypt_message(encr, bob.current_message_key)
print("Bob: Encrypted message: " + str(encr) + ", decrypted message: " + str(decr))
bob.turn_ratchet()
print("Bob: Ratchet turned. New chain key: " + str(bob.current_chain_key) + ", new message key: " + str(
    bob.current_message_key))
