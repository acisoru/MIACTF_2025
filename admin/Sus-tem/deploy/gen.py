import os
import random
import string

TARGET_DIR = "./scripts"
TOP_LEVEL_DIRS = 20
SUB_LEVEL_DIRS = 20
FAKE_SCRIPTS = 30

FAKE_NAMES = [
    "sys-update.sh", "backup.sh", "network-monitor.sh", "cleanup-logs.sh",
    "cron-helper.sh", "disk-check.sh", "package-updater.sh", "user-session.sh",
    "cache-clear.sh", "system-maintenance.sh", "log-rotate.sh",
    "service-restart.sh", "cpu-check.sh", "memory-check.sh",
    "error-reporter.sh", "temp-monitor.sh", "startup-helper.sh",
    "security-scan.sh", "ssh-helper.sh", "data-sync.sh"
]

def generate_fake_flag():
    chars = string.ascii_letters + string.digits
    return "miactf{"+ ''.join(random.choices(chars, k=16)) + "}"

os.makedirs(TARGET_DIR, exist_ok=True)

for top_num in range(1, TOP_LEVEL_DIRS + 1):
    top_dir = os.path.join(TARGET_DIR, f"folder_{top_num}")
    os.makedirs(top_dir, exist_ok=True)

    for sub_num in range(1, SUB_LEVEL_DIRS + 1):
        sub_dir = os.path.join(top_dir, f"subfolder_{sub_num}")
        os.makedirs(sub_dir, exist_ok=True)

        for _ in range(FAKE_SCRIPTS):
            base_name = random.choice(FAKE_NAMES)

            if random.choice([True, False]):
                base_name = f".{base_name}"

            name_part = os.path.splitext(base_name)[0]
            random_suffix = random.randint(0, 32767)
            script_name = f"{name_part}_{random_suffix}.sh"
            script_path = os.path.join(sub_dir, script_name)

            content = f"""#!/bin/sh
while true; do
    echo "{generate_fake_flag()}"
    sleep 1
    echo "Running system check..."
    sleep 1
    echo "System task completed."
    sleep 1
done
"""
            with open(script_path, "w") as f:
                f.write(content)

print(f"Done! {TOP_LEVEL_DIRS} top-level directories created, each with {SUB_LEVEL_DIRS} subdirectories containing {FAKE_SCRIPTS} scripts.")