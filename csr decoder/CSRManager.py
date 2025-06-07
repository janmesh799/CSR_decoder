import csv
import re

class CSRManager:
    def __init__(self, data_filename='./Database/data.csv'):
        self.data_filename = data_filename

    def read_csrs(self):
        with open(self.data_filename, mode='r') as file:
            csv_reader = csv.DictReader(file)
            return [row for row in csv_reader]

    def add_csr(self, curr_csr):
        if self.check_csr(curr_csr):
            print("CSR already exists")
            raise ValueError("CSR already exist")

        clean_csr = self.clean_csr(curr_csr)
        if isinstance(clean_csr, dict) and "error" in clean_csr:
            print(f"Error: {clean_csr['error']}")
            return

        csrs = self.read_csrs()
        csrs.append({"csr": clean_csr})

        with open(self.data_filename, mode='w', newline='') as file:
            fieldnames = ['csr']
            csv_writer = csv.DictWriter(file, fieldnames=fieldnames)
            csv_writer.writeheader()
            csv_writer.writerows(csrs)

    def check_csr(self, curr_csr):
        csrs = self.read_csrs()
        clean_csr = self.clean_csr(curr_csr)
        return any(csr['csr'] == clean_csr for csr in csrs)

    def clean_csr(self, curr_csr):
        try:
            if not isinstance(curr_csr, str):
                raise ValueError("CSR input must be a string.")

            private_key_patterns = [
                "-----BEGIN PRIVATE KEY-----",
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----BEGIN EC PRIVATE KEY-----"
            ]
            if any(pat in curr_csr for pat in private_key_patterns):
                raise ValueError("Input appears to be a private key, not a CSR. Please provide a valid CSR.")

            csr_pem_cleaned = re.sub(r'-----[^-]+-----', '', curr_csr).replace('\n', '')
            return csr_pem_cleaned

        except Exception as e:
            return {"error": str(e)}




############# usage ###############

# csr_manager = CSRManager()
# csr_manager.add_csr(your_csr_string)
