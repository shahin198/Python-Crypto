# Python-Crypto
Python Crypto using PyCryptodome 
# install PyCryptodome
$ sudo apt-get install build-essential libgmp3-dev python3-dev

$ pip install pycryptodomex

$ python3 -m Cryptodome.SelfTest

# Example.......
from Cryptodome.PublicKey import RSA

secret_code = "Unguessable"

key = RSA.generate(2048)

encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

file_out = open("rsa_key.bin", "wb")
file_out.write(encrypted_key)

print(key.publickey().export_key())

print("private key: ",key.export_key())
