#!/usr/bin/env python3
"""Unit tests"""

import unittest
from math import gcd, lcm

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime as get_prime

import mindpq

class TestMindPQ(unittest.TestCase):
    """Test cases for mindpq"""

    def test_factor(self) -> None:
        """Test factorisation via pairwise GCD"""
        p = 2
        q_1, q_2 = 3, 5
        moduli = [p * q_1, p * q_2]
        factors = mindpq.factor(moduli)
        self.assertIn((p, q_1), factors)
        self.assertIn((p, q_2), factors)
        self.assertEqual(len(factors), 2)

    def test_cannot_factor(self) -> None:
        """Try to factor moduli without a common factor"""
        moduli = [2 * 3, 5 * 7]
        with self.assertRaises(RuntimeError):
            mindpq.factor(moduli)

    def test_key_construction(self) -> None:
        """Construct a private RSA key"""
        key = mindpq.construct_private_key(e=3, p=5, q=11)
        self.assertTrue(key)

    def test_mini_end_to_end(self) -> None:
        """Generate a ciphertext and recover it"""
        message = b"yolo"
        bits = 512

        e = 3

        phi_n_1 = 0
        while gcd(e, phi_n_1) != 1:
            p, q_1 = get_prime(bits // 2 - 1), get_prime(bits // 2 + 1)
            phi_n_1 = lcm(p - 1, q_1 - 1)

        phi_n_2 = 0
        while gcd(e, phi_n_2) != 1:
            q_2 = get_prime(bits // 2 + 1)
            phi_n_2 = lcm(p - 1, q_2 - 1)

        keys = [mindpq.construct_private_key(e, p, q_1),
                mindpq.construct_private_key(e, p, q_2)]
        public_keys = [key.publickey() for key in keys]

        ciphertext = PKCS1_OAEP.new(keys[0]).encrypt(message)

        factors = mindpq.factor([key.n for key in keys])
        recovered_keys = mindpq.construct_private_keys(public_keys[0].e, factors)

        self.assertEqual(recovered_keys, keys)

        message_prime = mindpq.decrypt(recovered_keys[0], ciphertext)
        self.assertEqual(message, message_prime)

    def test_end_to_end(self) -> None:
        """Run through the whole attack"""
        public_keys = mindpq.import_keys()

        self.assertEqual(len(set(key.e for key in public_keys)), 1)

        # Factorise moduli and get corresponding private keys
        factors = mindpq.factor([key.n for key in public_keys])
        keys = mindpq.construct_private_keys(public_keys[0].e, factors)

        for public_key, key in zip(public_keys, keys):
            self.assertEqual(public_key, key.publickey())

        message_str = mindpq.decrypt_all(keys).decode()
        self.assertEqual("FLAG{", message_str[:5])

if __name__ == "__main__":
    unittest.main(verbosity=2, buffer=True)
