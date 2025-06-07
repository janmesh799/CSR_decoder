import base64
import re
import json
import time
import hashlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from CSRManager import CSRManager


class CSRDecoder:
    def __init__(self, csr_pem: str):
        self.csr_pem = csr_pem
        self.csr = None
        self.csr_der = None

    def _is_private_key(self):
        private_key_patterns = [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----"
        ]
        return any(pat in self.csr_pem for pat in private_key_patterns)

    def _clean_pem(self):
        return re.sub(r'-----[^-]+-----', '', self.csr_pem).replace('\n', '')

    def _load_csr(self):
        self.csr_der = base64.b64decode(self._clean_pem())
        self.csr = x509.load_der_x509_csr(self.csr_der, default_backend())

    def _is_md5_used(self):
        return "MD5" in self.csr.signature_algorithm_oid._name.upper()

    def _is_valid_key_size(self, public_key):
        if isinstance(public_key, rsa.RSAPublicKey):
            return public_key.key_size >= 2048
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return public_key.key_size >= 224
        return False

    def _is_signature_valid(self):
        try:
            public_key = self.csr.public_key()
            hash_algorithm = self.csr.signature_hash_algorithm

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    self.csr.signature,
                    self.csr.tbs_certrequest_bytes,
                    padding.PKCS1v15(),
                    hash_algorithm
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    self.csr.signature,
                    self.csr.tbs_certrequest_bytes,
                    ec.ECDSA(hash_algorithm)
                )
            else:
                raise ValueError("Unsupported key type for signature verification.")

            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def decode(self):
        
        try:
            if not isinstance(self.csr_pem, str):
                raise ValueError("CSR input must be a string.")
            
            if self._is_private_key():
                raise ValueError("Input appears to be a private key, not a CSR. Please provide a valid CSR.")
            csrManager = CSRManager()
            csrManager.add_csr(self.csr_pem)
            self._load_csr()
            subject_info = {attr.oid._name: attr.value for attr in self.csr.subject}
            public_key = self.csr.public_key()
            public_key_type = public_key.__class__.__name__
            key_size = public_key.key_size

            fingerprint_sha1 = hashlib.sha1(self.csr_der).hexdigest().upper()
            fingerprint_md5 = hashlib.md5(self.csr_der).hexdigest().upper()

            try:
                ext = self.csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sansDNS = ext.value.get_values_for_type(x509.DNSName)
                sansIP = ext.value.get_values_for_type(x509.IPAddress)
            except x509.ExtensionNotFound:
                sansDNS, sansIP = [], []

            result = {
                "Subject": subject_info,
                "Fingerprint (SHA-1)": ":".join(a + b for a, b in zip(fingerprint_sha1[::2], fingerprint_sha1[1::2])),
                "Fingerprint (MD5)": ":".join(a + b for a, b in zip(fingerprint_md5[::2], fingerprint_md5[1::2])),
                "SANS_DNS": sansDNS,
                "SANS_IP": sansIP,
                "public_key": {
                    "type": public_key_type,
                    "key_size": key_size
                },
                "checks": {
                    "Key Size": self._is_valid_key_size(public_key),
                    "Signature": self._is_signature_valid(),
                    "MD5": not self._is_md5_used()
                }
            }

            return result

        except Exception as e:
            return {"error": str(e)}

    def save_to_file(self, data: dict, folder: str = "decoded_csr"):
        common_name = data.get("Subject", {}).get("commonName", "unknown")
        timestamp = time.strftime("%Y%m%d%H%M%S")
        filename = f"{folder}/{common_name}_decoded_csr_{timestamp}.json"
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"CSR details saved to {filename}")
        
        
################## usage ###############

# from sample_csr import csr_pem

csr = """-----BEGIN NEW CERTIFICATE REQUEST-----
MIICmzCCAYMCAQAwVjELMAkGA1UEBhMCTk8xDTALBgNVBAcTBE9zbG8xFTATBgNV
BAoTDEROQiBCYW5rIEFTQTEhMB8GA1UEAxMYc3Rlc3QuZmlkczIuZG5iZmluYW5z
Lm5vMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxElIPNbpdE82v99e
MGWeM5yT1sviF+wdD9JvHZYUdUY6q+8xuYODtB1TNnGvdySDXhmyxejzuCJTYsPa
Mq2lLhYkQwRNfsLMfIh3nU2nt/u8stVqtVWm3RUk2YUzWNE+oLg3XLs97xqVAASs
cPm8swri3e26E3HspCaBGrpncwOUuYhy/uytwN6bO6hHZPNzwHU/xPpmThnKPhdP
RqjjNglzbZGCVZamURz+4tfp1sgzKTiuo/occsAXWz+WmY2IxQq4hKitSz5HMH+V
dbwq+SxfvZqpTv/E79aVxAbZVf/WV2pvXUTeyO6zBIzIS1VGoRhynfb16ufwtIge
HitajQIDAQABoAAwDQYJKoZIhvcNAQEFBQADggEBAHfhKdPUVvHWsmin/vbgfGUh
f/ffDN3gIobagUnX2Oul1Merv5MPa0FX9UCULjBqBWI+zgFlGAnTXZVf4/xdSsfq
FDDpp2l3y//RKH6C9YrEo+ufLMiYkUlVNRD3P2R3+fiA0r85DdATJDAdK/IILlld
68OyV6vGeJ+WsHZA7nqPgmdcUmb27QcXhjLFHUY2jrHVN76DV7GcknGvhjqhi//M
s6Bms8Y2OJBozm7/rkDMLoUOTM4wVNTm1NeuBnhHeW6qfFLhHxwIwDZ45vbkLy3t
rNz5fbQRWmDNN1nBiHSZGrUmhnh4fahcnSjQ/rQxeHTPJt7rLnO9s4lQmtPqjwE=
-----END NEW CERTIFICATE REQUEST-----"""

decoder = CSRDecoder(csr)
data = decoder.decode()

print("Decoded CSR Information:", data)

if "error" not in data:
    decoder.save_to_file(data)

