from pypykatz import pypykatz

def parse_sam_file(sam_file_path, system_file_path):
    try:
        # Parse the SAM file using the SYSTEM file for decryption
        sam_parser = pypykatz.sam(sam_file_path, system_file=system_file_path)
        sam_parser.dump()

        # Print user account information
        for user in sam_parser.users:
            print(f"Username: {user.username}")
            print(f"RID: {user.rid}")
            print(f"LM Hash: {user.lmhash}")
            print(f"NTLM Hash: {user.nthash}")
            print("-" * 40)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    sam_file_path = r"windows\SAM"       # Replace with the path to your SAM file
    system_file_path = r"windows\SYSTEM" # Replace with the path to your SYSTEM file
    parse_sam_file(sam_file_path, system_file_path)