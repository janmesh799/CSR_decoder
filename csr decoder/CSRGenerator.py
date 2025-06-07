import json
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec


class CSRGenerator:
    def __init__(self, config_json: str):
        self.config = json.loads(config_json)
        self.private_key = None
        self.csr = None
        self.output_folder = f"csr/csr_generation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.output_folder, exist_ok=True)

    def _get_hash_algorithm(self):
        hash_algorithms = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512()
        }
        return hash_algorithms.get(self.config["hash_algorithm"].lower(), hashes.SHA256())

    def _generate_private_key(self):
        algo = self.config["algorithm"].lower()
        if algo == "rsa":
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.config["key_size"]
            )
        elif algo == "ecc":
            ecc_curves = {
                "secp256r1": ec.SECP256R1(),
                "secp384r1": ec.SECP384R1(),
                "secp521r1": ec.SECP521R1()
            }
            curve = ecc_curves.get(self.config.get("ecc_curve", "secp256r1").lower(), ec.SECP256R1())
            self.private_key = ec.generate_private_key(curve)
        else:
            raise ValueError("Unsupported algorithm. Choose 'rsa' or 'ecc'.")

    def _build_csr(self):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.config["country"]),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.config["state"]),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.config["locality"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config["organization"]),
            x509.NameAttribute(NameOID.COMMON_NAME, self.config["common_name"]),
        ])

        builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

        if "alternative_names" in self.config:
            san = x509.SubjectAlternativeName([
                x509.DNSName(name) for name in self.config["alternative_names"]
            ])
            builder = builder.add_extension(san, critical=False)

        self.csr = builder.sign(self.private_key, self._get_hash_algorithm())

    def _save_private_key(self):
        key_path = os.path.join(self.output_folder, "private_key.pem")
        with open(key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    def _save_csr(self):
        csr_path = os.path.join(self.output_folder, "csr.pem")
        with open(csr_path, "wb") as f:
            f.write(self.csr.public_bytes(serialization.Encoding.PEM))

    def generate(self):
        self._generate_private_key()
        self._build_csr()
        self._save_private_key()
        self._save_csr()
        print(f"CSR and Private Key generated successfully in: {self.output_folder}")




######## usage ############33
json_data = '''
{
    "algorithm": "ecc",
    "ecc_curve": "secp521r1",
    "hash_algorithm": "sha512",
    "country": "US",
    "state": "California",
    "locality": "San Francisco",
    "organization": "Example Inc.",
    "common_name": "example.com",
    "alternative_names": ["example.com", "www.example.com"]
}
'''

generator = CSRGenerator(json_data)
generator.generate()
