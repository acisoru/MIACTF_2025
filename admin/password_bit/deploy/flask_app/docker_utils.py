import docker
import time
import threading
from config import (PORT_IN_CONTAINER, PORT_RANGE, CONTAINER_MEMORY_LIMIT, 
                   CONTAINER_SWAP_LIMIT, CONTAINER_CPU_LIMIT, CONTAINER_PIDS_LIMIT,
                   ENABLE_NO_NEW_PRIVILEGES, ENABLE_READ_ONLY, ENABLE_TMPFS, TMPFS_SIZE,
                   DROP_ALL_CAPABILITIES, CAP_NET_BIND_SERVICE, CAP_CHOWN)
from database import execute_query, remove_container_from_db

client = docker.from_env()
used_ports = set()

# Check if port is free
def is_port_free(port):
    for container in client.containers.list():
        container_ports = container.attrs.get('NetworkSettings', {}).get('Ports', {})
        for port_binding in container_ports.get(f"{PORT_IN_CONTAINER}/tcp", []):
            if port_binding['HostPort'] == str(port):
                return False
    return True

# Get a free port
def get_free_port():
    available_ports = list(set(PORT_RANGE) - used_ports)
    for port in available_ports:
        if is_port_free(port):
            used_ports.add(port)
            return port
    return None

# Remove a container
def remove_container(container_id, port):
    try:
        container = client.containers.get(container_id)
        container.remove(force=True)
        print(f"[SUCCESS] Container {container_id} removed.")
    except docker.errors.NotFound:
        print(f"[WARNING] Container {container_id} not found in Docker, but still in database.")

    used_ports.discard(port)

    execute_query("DELETE FROM containers WHERE id = ?", (container_id,))
    print(f"[SUCCESS] Container {container_id} removed from database.")

# Automatically remove container after expiration time
def auto_remove_container(container_id, port):
    try:
        while True:
            container_data = execute_query("SELECT expiration_time FROM containers WHERE id = ?", (container_id,), fetchone=True)
            if not container_data:
                print(f"[ERROR] Container {container_id} not found in database. Stopping thread.")
                return  # Exit the thread

            expiration_time = container_data[0]

            current_time = int(time.time())
            time_to_wait = expiration_time - current_time

            if time_to_wait <= 0:
                break  # Time expired - remove container

            print(f"[INFO] Container {container_id} will be checked again in 30 sec. Time left: {time_to_wait}s")
            time.sleep(min(time_to_wait, 30))  # Check every 30 seconds or until time expires

        print(f"[INFO] Removing container {container_id} due to expiration.")
        remove_container(container_id, port)

    except Exception as e:
        print(f"[ERROR] Unexpected error in auto_remove_container: {e}")

# Get container status
def get_container_status(container_id):
    try:
        container = client.containers.get(container_id)
        return {
            'status': container.status,
            'running': container.status == 'running'
        }
    except docker.errors.NotFound:
        return {
            'status': 'not_found',
            'running': False
        }
    except Exception as e:
        print(f"[ERROR] Error getting container status: {e}")
        return {
            'status': 'error',
            'running': False
        }

# Configure security options for container
def get_container_security_options():
    security_options = []
    
    # Add no-new-privileges if enabled
    if ENABLE_NO_NEW_PRIVILEGES:
        security_options.append("no-new-privileges:true")
    
    # We're not adding a seccomp profile to use Docker's default implicitly
    
    return security_options

# Configure container capabilities
def get_container_capabilities():
    capabilities = {
        'drop_all': DROP_ALL_CAPABILITIES,
        'add': []
    }
    
    # Add capabilities if needed
    if CAP_NET_BIND_SERVICE:
        capabilities['add'].append('NET_BIND_SERVICE')
    
    if CAP_CHOWN:
        capabilities['add'].append('CHOWN')
    
    return capabilities

# Configure container tmpfs if enabled
def get_container_tmpfs():
    if not ENABLE_TMPFS:
        return None
    
    return {'/tmp': f'exec,size={TMPFS_SIZE}'}
