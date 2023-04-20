import random
from typing import Optional

# prime number in hexadecimal representation for group 14
p: int = int("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
             "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
             "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
             "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
             "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
             "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
             "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)
# primitive root for group 14
g: int = 2


class DiffieHellmanParticipant:
    def __init__(self) -> None:
        self.private_key: int = random.getrandbits(220)  # recommended exponent size: 220 or 320 bit
        self.public_key: int = pow(g, self.private_key, p)
        self.shared_secret_key: Optional[int] = None

    def generate_shared_secret(self, other_public_key: int) -> None:
        self.shared_secret_key = pow(other_public_key, self.private_key, p)


# Key generation
alice: DiffieHellmanParticipant = DiffieHellmanParticipant()
bob: DiffieHellmanParticipant = DiffieHellmanParticipant()

# Shared secret generation
bob.generate_shared_secret(other_public_key=alice.public_key)
alice.generate_shared_secret(other_public_key=bob.public_key)

assert alice.shared_secret_key == bob.shared_secret_key
print("shared secret:", hex(alice.shared_secret_key))
