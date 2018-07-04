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
Generate an RSA  public key and private key
``` 
from Cryptodome.PublicKey import RSA
key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)

```
 Encrypt and decrypt data with RSA

```
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
data = "I met aliens in UFO. Here is the map.".encode("utf-8")
file_out = open("encrypted_data.bin", "wb")
recipient_key = RSA.import_key(open("receiver.pem").read())
session_key = get_random_bytes(16)
# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)
# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[ file_out.write(x)for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

# decrypt here................
# from Cryptodome.PublicKey import RSA
# from Cryptodome.Cipher import AES, PKCS1_OAEP
file_in = open("encrypted_data.bin", "rb")
private_key = RSA.import_key(open("private.pem").read())
enc_session_key, nonce, tag, ciphertext = \
[ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)
# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(data.decode("utf-8"))
```
