from routes import app
from database import init_db, execute_query
import docker
import signal
import sys
import atexit

# Initialize Docker client
client = docker.from_env()

# Function to cleanup all user containers
def cleanup_all_containers():
    print("Cleaning up all user containers...")
    try:
        # Get all container IDs from the database
        containers = execute_query("SELECT id FROM containers")
        
        # Remove each container
        for container_id in containers:
            try:
                container = client.containers.get(container_id[0])
                container.remove(force=True)
                print(f"Removed container {container_id[0]}")
            except:
                print(f"Failed to remove container {container_id[0]}")
        
        # Clear the database
        execute_query("DELETE FROM containers")
        print("All containers cleaned up successfully")
    except Exception as e:
        print(f"Error during cleanup: {e}")

# Register the cleanup function to run on exit
atexit.register(cleanup_all_containers)

# Handle SIGTERM and SIGINT properly
def signal_handler(sig, frame):
    print("Received shutdown signal, cleaning up...")
    cleanup_all_containers()
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    init_db()  # Initialize the database
    app.run(host="0.0.0.0", port=5000, debug=True)
