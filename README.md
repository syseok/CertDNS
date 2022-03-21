# DNS Proxy Checking Records with SSL certificate
DNS

# Signer
sign your records with your corresponding private key from the digital certificate.

# Validator
DNS proxy validating signature and CERT record.

change line 143 to your CA certificate and intermediate certificate file.

How to run

python Proxy.py "DNS server IP" "Port number"

example) python Proxy.py 1.1.1.1 5757

# Dependencies
python3.8

dnslib - from https://github.com/paulc/dnslib

PyCrypto - from https://pypi.org/project/pycrypto/
