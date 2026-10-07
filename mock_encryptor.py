import os
import time
import random
import string

def create_dummy_files(target_dir, count=5):
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    print(f"Creating {count} dummy files in {target_dir}...")
    for i in range(count):
        filepath = os.path.join(target_dir, f"dummy_doc_{i}.txt")
        with open(filepath, 'w') as f:
            # Low entropy text
            text = "This is a normal text file with normal words. " * 50
            f.write(text)
    time.sleep(2)

def simulate_encryption(target_dir):
    print("Simulating ransomware encryption behavior...")
    for filename in os.listdir(target_dir):
        if filename.startswith("dummy_doc_"):
            filepath = os.path.join(target_dir, filename)
            
            # Read original (simulate read)
            with open(filepath, 'r') as f:
                content = f.read()
                
            # Generate high entropy bytes (simulate encryption)
            # Random bytes have very high entropy
            encrypted_data = os.urandom(len(content) + 1024)
            
            # Write back (simulate overwrite)
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
                
            print(f"Encrypted: {filename}")
            time.sleep(1) # small delay between files

if __name__ == "__main__":
    target = os.path.join(os.getcwd(), "test_monitor_dir")
    create_dummy_files(target)
    simulate_encryption(target)
    print("Simulation complete.")
