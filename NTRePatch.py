import os
import shutil
import logging
from pypykatz.registry.sam import SamHive

# Setup logging
log_file = "ntrepatch.log"
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger()

def log_and_print(message, level="info"):
    """Log the message and print it to the console."""
    if level == "info":
        logger.info(message)
    elif level == "error":
        logger.error(message)
    elif level == "warning":
        logger.warning(message)
    print(message)

# Step 1: Detect Windows partition
def find_windows_partition():
    partitions = os.popen("blkid -o device").read().strip().split("\n")
    for part in partitions:
        if "ntfs" in os.popen(f"blkid {part}").read().lower():
            log_and_print(f"Found Windows partition: {part}")
            return part
    log_and_print("Windows partition not found!", "error")
    return None

windows_partition = find_windows_partition()
if not windows_partition:
    exit(1)

# Step 2: Fix NTFS and Mount
mount_point = "/mnt/windows"
os.makedirs(mount_point, exist_ok=True)

log_and_print("Fixing NTFS issues before mounting...")
os.system(f"ntfsfix {windows_partition}")

log_and_print(f"Mounting Windows partition at {mount_point}...")
mount_result = os.system(f"mount -o remove_hiberfile -t ntfs-3g {windows_partition} {mount_point}")
if mount_result != 0:
    log_and_print("Failed to mount Windows partition! Exiting...", "error")
    exit(1)

# Step 3: Define file paths
sam_path = f"{mount_point}/Windows/System32/config/SAM"
system_path = f"{mount_point}/Windows/System32/config/SYSTEM"

# Step 4: Backup before modification
backup_folder = f"{mount_point}/Windows_Backup"
os.makedirs(backup_folder, exist_ok=True)

try:
    shutil.copy(sam_path, f"{backup_folder}/SAM.bak")
    shutil.copy(system_path, f"{backup_folder}/SYSTEM.bak")
    log_and_print(f"Backup created at {backup_folder}")
except Exception as e:
    log_and_print(f"Failed to create backup: {e}", "error")
    exit(1)

# Step 5: Open SAM file
try:
    sam = SamHive.from_sam_system(sam_path, system_path)
    users = sam.users
    log_and_print("Successfully opened SAM file.")
except Exception as e:
    log_and_print(f"Error reading SAM file: {e}", "error")
    exit(1)

# Step 6: Find the first user account
admin_rid = None
for user in users.values():
    log_and_print(f"Username: {user.username}, RID: {user.rid}, NT Hash: {user.nt_hash}")
    if user.username.lower() == "administrator":
        admin_rid = user.rid

if not admin_rid and users:
    admin_rid = list(users.keys())[0]  # Pick first available user

if not admin_rid:
    log_and_print("No user account found!", "error")
    exit(1)

# Step 7: Remove Password
try:
    user = sam.get_user(admin_rid)
    user.nt_hash = None  # Clear password
    sam.export_sam(sam_path)  # Save SAM file
    log_and_print("Password removed successfully!")
except Exception as e:
    log_and_print(f"Error modifying SAM file: {e}", "error")
    exit(1)

# Step 8: Unmount Windows partition
log_and_print(f"Unmounting {mount_point}...")
unmount_result = os.system(f"umount {mount_point} || umount -l {mount_point}")
if unmount_result != 0:
    log_and_print("Failed to unmount the partition properly. You may need to do it manually.", "warning")

log_and_print("Done! Reboot into Windows.")
