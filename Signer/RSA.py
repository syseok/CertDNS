from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

private_key = RSA.importKey(open("private key here").read())

record = b'record here'
h = SHA256.new(record)
signature = pkcs1_15.new(private_key).sign(h)

print(base64.b64encode(signature))
