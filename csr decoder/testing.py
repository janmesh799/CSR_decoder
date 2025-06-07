import time
import json
from TestCases import testCases
from CSRDecoder import CSRDecoder

# Generate a timestamp
timestamp = time.strftime('%Y-%m-%d_%H-%M-%S')
filename = f"testing_results/testing_result_{timestamp}.txt"

# Open the file for writing
with open(filename, "w") as file:
    for i, item in enumerate(testCases):
        csr_data = item["data"]
        csr_desc = item["description"]
        decoder = CSRDecoder(csr_data)
        decoded_csr = decoder.decode()
        
        # Write to file
        file.write(f"Test Case {i+1}: {csr_desc}\n")
        file.write(json.dumps(decoded_csr, indent=4))
        file.write("\n\n")

print(f"Results saved in {filename}")