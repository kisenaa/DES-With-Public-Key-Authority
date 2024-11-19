import secrets
import math

# reference :https://pythonmania.org/python-program-for-rsa-algorithm/

class RSA_Algorithm():
    @staticmethod
    def is_prime(n):
        if n <= 1:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    @staticmethod
    def generate_prime():
        while True:
            prime = secrets.randbits(16) 
            if RSA_Algorithm.is_prime(prime):
                return prime

    @staticmethod
    def generate_keypair():
        p = RSA_Algorithm.generate_prime()
        q = RSA_Algorithm.generate_prime()
        n = p * q
        phi = (p - 1) * (q - 1)

        while True:
            e = secrets.randbelow(phi - 1) + 2
            if math.gcd(e, phi) == 1:
                break

        d = pow(e, -1, phi)
        return ((n, e), (n, d))

    @staticmethod
    def encrypt(message, public_key):
        n, e = public_key
        encrypted_message = [pow(ord(char), e, n) for char in message]
        return encrypted_message

    @staticmethod
    def decrypt(encrypted_message, private_key):
        n, d = private_key
        decrypted_message = ''.join([chr(pow(char, d, n)) for char in encrypted_message])
        return decrypted_message