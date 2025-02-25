#from pypykatz.registry.offline_parser import OffineRegistry

# Paths to registry hives
#system_hive_path = "windows\SYSTEM"

# Load the registry hives
#registry = OffineRegistry.from_files(system_hive_path, security_path=security_hive_path)

# Print extracted secrets
#print(registry)

##from pypykatz.registry.offline_parser import OffineRegistry

# Paths to the SYSTEM and SAM registry hives
##sam_hive_path = r"windows\SAM"
##system_hive_path = r"windows\SYSTEM"

 #Load the registry hives
##registry = OffineRegistry.from_files(system_hive_path, sam_path=sam_hive_path)

 #Print extracted credentials
#print(registry)

import sys
import os
from pypykatz.registry.offline_parser import OffineRegistry
from tabulate import tabulate

def extract_sam_users(system_hive_path, sam_hive_path, security_hive_path, software_hive_path):
    # Ensure all hive files exist
    for path in [system_hive_path, sam_hive_path, security_hive_path, software_hive_path]:
        if not os.path.exists(path):
            print(f"ERROR: Missing registry hive file: {path}")
            sys.exit(1)
    
    # Load registry from SYSTEM, SAM, SECURITY, and SOFTWARE hives
    registry = OffineRegistry.from_files(
        system_hive_path, 
        sam_path=sam_hive_path, 
        security_path=security_hive_path, 
        software_path=software_hive_path
    )
    
    # Retrieve user secrets
    registry.get_secrets()
    
    # Store extracted user information
    users_data = []
    for user in registry.secrets:
        users_data.append([user.username, user.rid, user.nt_hash.hex(), user.lm_hash.hex()])
    
    # Print extracted user information in table format
    print("\nExtracted User Information:")
    print(tabulate(users_data, headers=["Username", "RID", "NT Hash", "LM Hash"], tablefmt="grid"))

if __name__ == "__main__":
    # Define static file paths for SYSTEM, SAM, SECURITY, and SOFTWARE hives
    system_hive_path = r"windows\SYSTEM"
    sam_hive_path = r"windows\SAM"
    security_hive_path = r"windows\SECURITY"
    software_hive_path = r"windows\SOFTWARE"
    
    extract_sam_users(system_hive_path, sam_hive_path, security_hive_path, software_hive_path)





