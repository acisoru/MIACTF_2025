import os
from dotenv import load_dotenv

# Try to load from .env file (root level)
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)

# Container settings
LEAVE_TIME = int(os.getenv('LEAVE_TIME', 1800))  # Default: 30 minutes
ADD_TIME = int(os.getenv('ADD_TIME', 600))      # Default: 10 minutes
IMAGES_NAME = os.getenv('IMAGES_NAME', "localhost/generic_ctf_task:latest")
FLAG = os.getenv('FLAG', 'CTF{generic_flag_for_testing}')
PORT_IN_CONTAINER = int(os.getenv('PORT_IN_CONTAINER', '80'))
PORT_RANGE = range(int(os.getenv('START_RANGE', 9000)), int(os.getenv('STOP_RANGE', 10001)))
DB_PATH = os.getenv('DB_PATH', './data/containers.db')

# Rate limiting
MAX_CONTAINERS_PER_HOUR = int(os.getenv('MAX_CONTAINERS_PER_HOUR', 5))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', 3600))  # 1 hour in seconds

# CTF Challenge title and description
CHALLENGE_TITLE = os.getenv('CHALLENGE_TITLE', 'Generic CTF Challenge')
CHALLENGE_DESCRIPTION = os.getenv('CHALLENGE_DESCRIPTION', 
                                'Solve the challenge to find the hidden flag!')

# Resource limits for containers
CONTAINER_MEMORY_LIMIT = os.getenv('CONTAINER_MEMORY_LIMIT', '512M')
CONTAINER_SWAP_LIMIT = os.getenv('CONTAINER_SWAP_LIMIT', '512M')
CONTAINER_CPU_LIMIT = float(os.getenv('CONTAINER_CPU_LIMIT', '0.5'))
CONTAINER_PIDS_LIMIT = int(os.getenv('CONTAINER_PIDS_LIMIT', '50'))

# Security options
ENABLE_NO_NEW_PRIVILEGES = os.getenv('ENABLE_NO_NEW_PRIVILEGES', 'true').lower() == 'true'
ENABLE_READ_ONLY = os.getenv('ENABLE_READ_ONLY', 'false').lower() == 'true'
ENABLE_TMPFS = os.getenv('ENABLE_TMPFS', 'true').lower() == 'true'
TMPFS_SIZE = os.getenv('TMPFS_SIZE', '64M')

# Container capabilities
DROP_ALL_CAPABILITIES = os.getenv('DROP_ALL_CAPABILITIES', 'true').lower() == 'true'
CAP_NET_BIND_SERVICE = os.getenv('CAP_NET_BIND_SERVICE', 'true').lower() == 'true'
CAP_CHOWN = os.getenv('CAP_CHOWN', 'true').lower() == 'true'
