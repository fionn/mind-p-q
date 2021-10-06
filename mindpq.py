#!/usr/bin/env python3
"""Mind your ps and qs"""

from math import gcd, lcm

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import isPrime as is_prime

from batch_gcd import batch_gcd


def import_keys() -> list[RSA.RsaKey]:
    """Load public keys"""
    keys = []
    for i in range(23):
        with open(f"data/{i}.key", encoding="ascii") as fd:
            keys.append(RSA.import_key(fd.read()))
    return keys


def factor(moduli: list[int]) -> list[tuple[int, int]]:
    """Factorise moduli via batch GCD, returned at the same index"""
    factors: list[tuple[int, int]] = []
    gs = batch_gcd(moduli)
    for n, p in zip(moduli, gs):
        if p == 1:
            raise RuntimeError(f"Failed to factorise modulus {n}")
        if p < n:
            assert is_prime(p), p
            factors.append((p, n // p))
        elif p == n:
            factors.append(pairwise_gcd(n, moduli))
        else:
            raise RuntimeError("Batch GCD error")

    return factors


def pairwise_gcd(n: int, moduli: list[int]) -> tuple[int, int]:
    """Factorise n if it shares factors with any modulus"""
    for n_j in moduli:
        p = gcd(n, n_j)
        if 1 < p < n:
            q = n // p
            assert is_prime(p), p
            assert is_prime(q), q
            return (p, q)
    raise RuntimeError(f"Failed to factorise modulus {n}")


def construct_private_key(e: int, p: int, q: int) -> RSA.RsaKey:
    """Generate a private RSA key from its parameters"""
    d = pow(e, -1, lcm(p - 1, q - 1))
    return RSA.construct((p * q, e, d, p, q))


def construct_private_keys(e: int,
                           factors: list[tuple[int, int]]) -> list[RSA.RsaKey]:
    """Bulk private key creation"""
    keys = []
    for p_q in factors:
        private_key = construct_private_key(e, *p_q)
        keys.append(private_key)

    return keys


def decrypt(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    """RSA PLCS1 OAEP decryption"""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


def decrypt_all(keys: list[RSA.RsaKey]) -> bytes:
    """Iterate over all cyphertexts and concatenate their decryption"""
    message = b""
    for i, key in enumerate(keys):
        with open(f"data/{i}.enc", "rb") as fd:
            ciphertext = fd.read()
            message += decrypt(key, ciphertext)
    return message


def main() -> None:
    """Entry point"""
    public_keys = import_keys()

    # Ensure all keys have the same exponent.
    assert len(set(key.e for key in public_keys)) == 1

    # Factorise moduli and get corresponding private keys
    factors = factor([key.n for key in public_keys])
    keys = construct_private_keys(public_keys[0].e, factors)

    for public_key, key in zip(public_keys, keys):
        assert public_key == key.publickey()

    message = decrypt_all(keys)
    print(message.decode())


if __name__ == "__main__":
    main()
