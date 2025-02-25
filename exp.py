from pypykatz.registry.offline_parser import OffineRegistry

# Paths to the SYSTEM, SAM, SECURITY, and SOFTWARE registry hives
sam_hive_path = r"windows\SAM"
system_hive_path = r"windows\SYSTEM"
security_hive_path = r"windows\SECURITY"
software_hive_path = r"windows\SOFTWARE"

try:
    # Load the registry hives
    registry = OffineRegistry.from_files(
        system_hive_path, 
        sam_path=sam_hive_path, 
        security_path=security_hive_path, 
        software_path=software_hive_path
    )

    # Extract secrets (this keeps files open internally)
    registry.get_secrets()

    # Extract and print user data
    if hasattr(registry.sam, 'users'):
        for rid, user in registry.sam.users.items():
            print(f"RID: {rid}, Username: {user.username}, NT Hash: {user.nt_hash}, LM Hash: {user.lm_hash}")
    else:
        print("No users found in the SAM hive.")

except Exception as e:
    print(f"Error extracting secrets: {e}")
