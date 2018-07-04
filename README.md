# Python-Crypto
Python Crypto using PyCryptodome 

https://media.readthedocs.org/pdf/pycryptodome/latest/pycryptodome.pdf
# install PyCryptodome
``` 
$ sudo apt-get install build-essential libgmp3-dev python3-dev

$ pip install pycryptodomex

$ python3 -m Cryptodome.SelfTest
``` 
# Symmetrical Encryption
```
import json
from base64 import b64encode,b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad,unpad
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256

hash_object = SHA256.new(data=b'First')
# print(hash_object.digest())
data = b"secret"

# key = get_random_bytes(32)
key=hash_object.digest()
cipher = AES.new(key, AES.MODE_CBC)
# print(key)
ct_bytes = cipher.encrypt(pad(data, AES.block_size))

iv = b64encode(cipher.iv).decode('utf-8')

ct = b64encode(ct_bytes).decode('utf-8')

result = json.dumps({'iv':iv, 'ciphertext':ct})

print(result)

# We assume that the key was securely shared beforehand
try:

    b64 = json.loads(result)

    iv = b64decode(b64['iv'])

    ct = b64decode(b64['ciphertext'])

    cipher = AES.new(key, AES.MODE_CBC, iv)

    pt = unpad(cipher.decrypt(ct), AES.block_size)

    print("The message was: ", pt)
except:

    print("Incorrect decryption")
```
result: 
```
{"iv": "JAkWrF8CbKNeFT6wM/yRxQ==", "ciphertext": "9eK8c/hQb5QLgSedYh+Hgw=="}
The message was:  b'secret'
```
# Asymmetrical Encryption
``` 
from Cryptodome.PublicKey import RSA

secret_code = "Unguessable"

key = RSA.generate(2048)

encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

file_out = open("rsa_key.bin", "wb")
file_out.write(encrypted_key)

print(key.publickey().export_key())

print("private key: ",key.export_key()) 

```


