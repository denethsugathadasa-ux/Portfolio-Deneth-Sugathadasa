import hashlib
import time
import os

def calculate_sha256(filepath):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read in chunks so we don't crash on huge files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

def monitor_file(target_file):
    print(f"--- Monitoring Started for: {target_file} ---")
    
    # 1. Create the baseline (The 'Gold Standard' hash)
    baseline_hash = calculate_sha256(target_file)
    if not baseline_hash:
        print("Error: File not found. Please check the path.")
        return

    print(f"Baseline established: {baseline_hash[:10]}...")

    try:
        while True:
            time.sleep(2) # Check every 2 seconds
            current_hash = calculate_sha256(target_file)

            if current_hash != baseline_hash:
                print(f"\n[!] ALERT: FILE INTEGRITY COMPROMISED!")
                print(f"Time: {time.ctime()}")
                print(f"Status: Unauthorized modification detected.")
                # Update baseline if you want to acknowledge the change
                # baseline_hash = current_hash 
            else:
                print(".", end="", flush=True) # Heartbeat to show it's working
                
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

if __name__ == "__main__":
    # Change 'test.txt' to any file you want to protect
    file_to_watch = "test.txt" 
    
    # Create a test file if it doesn't exist
    if not os.path.exists(file_to_watch):
        with open(file_to_watch, "w") as f:
            f.write("Initial secure data.")
            
    monitor_file(file_to_watch)