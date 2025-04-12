#!/bin/bash

# deploy.sh - Deployment script for CTF Challenge Deployer
# Author: Claude
# Date: April 10, 2025
# 
# Enhanced to support multiple concurrent deployer instances on the same host
# without interference between instances.

# Terminal colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print styled messages
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if Docker is installed and running
check_docker() {
    log_info "Checking Docker installation..."
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH. Please install Docker and try again."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running or you don't have permission to use it."
        log_info "Try running the script with sudo or add your user to the docker group."
        exit 1
    fi
    
    log_success "Docker is installed and running."
}

# Determine which Docker Compose command to use
detect_docker_compose() {
    log_info "Detecting Docker Compose command..."
    
    if command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
        log_success "Using docker-compose command."
    elif docker compose version &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
        log_success "Using docker compose command."
    else
        log_error "Docker Compose is not installed. Please install Docker Compose and try again."
        exit 1
    fi
}

# Verify environment file exists and contains required variables
check_env_file() {
    log_info "Checking environment file..."
    
    if [ ! -f .env ]; then
        log_error ".env file not found. Deployment cannot continue."
        echo -e "${YELLOW}Please create an .env file with the required configuration before running this script.${NC}"
        echo -e "${YELLOW}See the README.md file for configuration instructions.${NC}"
        exit 1
    else
        log_success ".env file exists."
    fi
    
    # Check for required variables
    log_info "Validating environment variables..."
    
    # Source the .env file to get the variables
    source .env
    
    # List of required variables
    REQUIRED_VARS=("NETWORK_NAME" "NETWORK_SUBNET" "FLASK_APP_PORT" "PORT_IN_CONTAINER" "START_RANGE" "STOP_RANGE")
    MISSING_VARS=0
    
    for var in "${REQUIRED_VARS[@]}"; do
        if [ -z "${!var}" ]; then
            log_error "Required variable $var is not set in .env file."
            MISSING_VARS=$((MISSING_VARS+1))
        fi
    done
    
    if [ $MISSING_VARS -gt 0 ]; then
        log_error "$MISSING_VARS required variables are missing. Please check your .env file."
        exit 1
    else
        log_success "All required environment variables are set."
    fi
}

# Check for network conflicts and store port range information in Docker labels
check_network_conflicts() {
    log_info "Checking for network conflicts..."
    
    # Source the .env file if not already done
    if [ -z "$NETWORK_NAME" ] || [ -z "$NETWORK_SUBNET" ] || [ -z "$START_RANGE" ] || [ -z "$STOP_RANGE" ]; then
        source .env
    fi
    
    # Check for conflicting port ranges in other deployer networks
    log_info "Checking for port range conflicts with other deployers..."
    
    # Get all networks that might be CTF deployer networks
    CTF_NETWORKS=$(docker network ls --format "{{.Name}}" | grep -E "ctf_.*_network")
    
    for net in $CTF_NETWORKS; do
        # Skip our own network
        if [ "$net" = "$NETWORK_NAME" ]; then
            continue
        fi
        
        # Check if the network has a label with port range info
        PORT_RANGE_LABEL=$(docker network inspect "$net" | grep -A 3 "Labels" | grep "deployer.port.range" 2>/dev/null)
        
        if [ ! -z "$PORT_RANGE_LABEL" ]; then
            # Extract port range from label
            OTHER_START=$(echo "$PORT_RANGE_LABEL" | sed -E 's/.*"deployer.port.range": "([0-9]+)-([0-9]+)".*/\1/')
            OTHER_STOP=$(echo "$PORT_RANGE_LABEL" | sed -E 's/.*"deployer.port.range": "([0-9]+)-([0-9]+)".*/\2/')
            
            # Check for overlap
            if [ "$START_RANGE" -le "$OTHER_STOP" ] && [ "$STOP_RANGE" -ge "$OTHER_START" ]; then
                log_error "Port range conflict detected with network $net"
                log_error "Your range ($START_RANGE-$STOP_RANGE) overlaps with ($OTHER_START-$OTHER_STOP)"
                log_error "Please update your START_RANGE and STOP_RANGE in .env to avoid conflicts"
                exit 1
            fi
        else
            # Look for configuration files in the file system as a fallback
            # Get potential port range files in the system
            PORT_FILES=$(find /root -name "port_range.info" 2>/dev/null)
            
            for port_file in $PORT_FILES; do
                # Skip our own port file if exists
                if [ "$port_file" = "./data/port_range.info" ]; then
                    continue
                fi
                
                if [ -f "$port_file" ]; then
                    OTHER_START=$(head -1 "$port_file" | cut -d'-' -f1)
                    OTHER_STOP=$(head -1 "$port_file" | cut -d'-' -f2)
                    
                    # Check if values are valid numbers
                    if [[ "$OTHER_START" =~ ^[0-9]+$ ]] && [[ "$OTHER_STOP" =~ ^[0-9]+$ ]]; then
                        # Check for overlap
                        if [ "$START_RANGE" -le "$OTHER_STOP" ] && [ "$STOP_RANGE" -ge "$OTHER_START" ]; then
                            log_error "Port range conflict detected with $port_file"
                            log_error "Your range ($START_RANGE-$STOP_RANGE) overlaps with ($OTHER_START-$OTHER_STOP)"
                            log_error "Please update your START_RANGE and STOP_RANGE in .env to avoid conflicts"
                            exit 1
                        fi
                    fi
                fi
            done
        fi
    done
    
    # Check if our network already exists
    if docker network ls --format "{{.Name}}" | grep -q "^${NETWORK_NAME}$"; then
        log_info "Network $NETWORK_NAME already exists."
        
        # Check if network has containers attached
        if docker network inspect "$NETWORK_NAME" | grep -q '"Containers": {}'; then
            log_info "Network $NETWORK_NAME has no attached containers. Will reuse."
        else
            CONTAINERS=$(docker network inspect "$NETWORK_NAME" | grep -A 5 "Containers" | grep "Name" | cut -d'"' -f4)
            log_warning "Network $NETWORK_NAME has the following containers attached:"
            echo "$CONTAINERS"
            read -p "Continue anyway? This may impact running services. (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_error "Aborted by user due to network conflict."
                exit 1
            fi
        fi
    else
        log_info "Network $NETWORK_NAME does not exist yet."
        
        # Check if subnet conflicts with existing networks
        SUBNET_FIRST_OCTETS=$(echo "$NETWORK_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-2)
        CONFLICTING_NETWORKS=$(docker network ls --format "{{.Name}}" | xargs -I{} sh -c "docker network inspect {} | grep -q \"$SUBNET_FIRST_OCTETS\" && echo {}" 2>/dev/null)
        
        if [ ! -z "$CONFLICTING_NETWORKS" ]; then
            log_warning "Subnet $NETWORK_SUBNET may conflict with existing networks:"
            echo "$CONFLICTING_NETWORKS"
            read -p "Continue anyway? This may cause networking issues. (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_error "Aborted by user due to subnet conflict."
                exit 1
            fi
        fi
    fi
    
    # Save port range info to a file for other deployers to check
    mkdir -p data
    echo "${START_RANGE}-${STOP_RANGE}" > data/port_range.info
    
    log_success "Network conflict check completed."
}

# Check for port conflicts
check_port_conflicts() {
    log_info "Checking for port conflicts..."
    
    # Source the .env file if not already done
    if [ -z "$FLASK_APP_PORT" ] || [ -z "$START_RANGE" ] || [ -z "$STOP_RANGE" ]; then
        source .env
    fi
    
    PORT_CONFLICTS=0
    
    # Check FLASK_APP_PORT
    if netstat -tuln 2>/dev/null | grep -q ":$FLASK_APP_PORT " || ss -tuln 2>/dev/null | grep -q ":$FLASK_APP_PORT "; then
        log_warning "Port $FLASK_APP_PORT (FLASK_APP_PORT) is already in use."
        PORT_CONFLICTS=$((PORT_CONFLICTS+1))
    fi
    
    # Check DIRECT_TEST_PORT if set
    if [ ! -z "$DIRECT_TEST_PORT" ]; then
        if netstat -tuln 2>/dev/null | grep -q ":$DIRECT_TEST_PORT " || ss -tuln 2>/dev/null | grep -q ":$DIRECT_TEST_PORT "; then
            log_warning "Port $DIRECT_TEST_PORT (DIRECT_TEST_PORT) is already in use."
            PORT_CONFLICTS=$((PORT_CONFLICTS+1))
        fi
    fi
    
    # Check for conflicts in port range - this is critical and will cause immediate failure
    # Sample a few ports to avoid checking thousands
    SAMPLE_INTERVAL=$((($STOP_RANGE - $START_RANGE) / 10))
    SAMPLE_INTERVAL=$((SAMPLE_INTERVAL > 0 ? SAMPLE_INTERVAL : 1))
    
    PORT_RANGE_CONFLICT=false
    CONFLICTING_PORT=""
    
    for port in $(seq $START_RANGE $SAMPLE_INTERVAL $STOP_RANGE); do
        # Check if port is in use by Docker containers
        if docker ps --format "{{.Ports}}" | grep -q ":$port->"; then
            log_error "Port $port in range $START_RANGE-$STOP_RANGE is already used by a Docker container."
            PORT_RANGE_CONFLICT=true
            CONFLICTING_PORT=$port
            break
        fi
    done
    
    # Port range conflicts are critical - fail immediately
    if [ "$PORT_RANGE_CONFLICT" = true ]; then
        log_error "Port range conflict detected at port $CONFLICTING_PORT. This would prevent containers from being deployed correctly."
        log_error "Please update your START_RANGE and STOP_RANGE in .env to use a non-conflicting port range."
        exit 1
    fi
    
    # Handle other port conflicts (Flask app, direct test)
    if [ $PORT_CONFLICTS -gt 0 ]; then
        log_warning "Found $PORT_CONFLICTS potential port conflicts with the deployer interface."
        read -p "Continue anyway? This may cause port binding failures. (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Aborted by user due to port conflicts."
            exit 1
        fi
    else
        log_success "No obvious port conflicts detected."
    fi
}

# Safely clean up only our network if it exists and has no containers
safely_cleanup_network() {
    log_info "Safely cleaning up own network (if needed)..."
    
    # Source the .env file if not already done
    if [ -z "$NETWORK_NAME" ]; then
        source .env
    fi
    
    # Check if network exists
    if docker network ls --format "{{.Name}}" | grep -q "^${NETWORK_NAME}$"; then
        # Check if network has containers attached
        if docker network inspect "$NETWORK_NAME" | grep -q '"Containers": {}'; then
            log_info "Removing unused network $NETWORK_NAME."
            if docker network rm "$NETWORK_NAME" &>/dev/null; then
                log_success "Successfully removed network $NETWORK_NAME."
            else
                log_warning "Failed to remove network $NETWORK_NAME. Will try to reuse it."
            fi
        else
            log_info "Network $NETWORK_NAME has attached containers. Keeping it."
        fi
    else
        log_info "Network $NETWORK_NAME does not exist yet."
    fi
}

# Check if required directories exist
check_directories() {
    log_info "Checking required directories..."
    
    # Check if data directory exists, create if not
    if [ ! -d "data" ]; then
        mkdir -p data
        log_success "Created data directory."
    fi
}

# Build the Docker images with no-cache option
build_images() {
    log_info "Building Docker images with --no-cache option..."
    
    if $DOCKER_COMPOSE build --no-cache; then
        log_success "Docker images built successfully."
    else
        log_error "Failed to build Docker images."
        exit 1
    fi
}

# Start the containers
start_containers() {
    log_info "Starting Docker containers..."
    
    # Create a custom docker network with port range labels if not exists
    if ! docker network ls --format "{{.Name}}" | grep -q "^${NETWORK_NAME}$"; then
        log_info "Creating custom network with port range metadata..."
        docker network create \
            --subnet=${NETWORK_SUBNET} \
            --label "deployer.port.range=${START_RANGE}-${STOP_RANGE}" \
            --label "deployer.name=$(basename $(pwd))" \
            ${NETWORK_NAME} > /dev/null
    else
        # Update labels on existing network
        # This is more complex and may not be directly supported by Docker
        # We'll skip for now, but the network will be recreated if we remove it
        log_info "Using existing network. Note: port range metadata may not be updated."
    fi
    
    if $DOCKER_COMPOSE up -d; then
        log_success "Docker containers started successfully."
    else
        log_error "Failed to start Docker containers."
        exit 1
    fi
}

# Check if services are running properly
check_services() {
    log_info "Checking if services are running properly..."
    
    # Wait a bit for services to initialize
    sleep 5
    
    # Check if flask_app container is running
    if $DOCKER_COMPOSE ps | grep -q flask_app.*Up; then
        log_success "Flask application is running."
    else
        log_warning "Flask application may not be running correctly. Check the logs for details."
    fi
    
    # Check if generic_ctf_task container is running
    if $DOCKER_COMPOSE ps | grep -q generic_ctf_task.*Up; then
        log_success "Challenge task is running."
    else
        log_warning "Challenge task may not be running correctly. Check the logs for details."
    fi
}

# Verify ports are accessible
check_ports() {
    log_info "Verifying port accessibility..."
    
    # Get port values from environment if not already sourced
    if [ -z "$FLASK_APP_PORT" ] || [ -z "$DIRECT_TEST_PORT" ]; then
        source .env
    fi
    
    # Default values if not set
    FLASK_APP_PORT=${FLASK_APP_PORT:-6664}
    DIRECT_TEST_PORT=${DIRECT_TEST_PORT:-44444}
    
    # Check if ports are in use
    if netstat -tuln 2>/dev/null | grep -q ":$FLASK_APP_PORT " || ss -tuln 2>/dev/null | grep -q ":$FLASK_APP_PORT "; then
        log_success "Flask application port $FLASK_APP_PORT is accessible."
    else
        log_warning "Flask application port $FLASK_APP_PORT might not be accessible. Check firewall settings."
    fi
    
    if netstat -tuln 2>/dev/null | grep -q ":$DIRECT_TEST_PORT " || ss -tuln 2>/dev/null | grep -q ":$DIRECT_TEST_PORT "; then
        log_success "Direct test port $DIRECT_TEST_PORT is accessible."
    else
        log_warning "Direct test port $DIRECT_TEST_PORT might not be accessible. Check firewall settings."
    fi
}

# Print access information
print_access_info() {
    # Get port values from environment if not already sourced
    if [ -z "$FLASK_APP_PORT" ] || [ -z "$DIRECT_TEST_PORT" ]; then
        source .env
    fi
    
    # Default values if not set
    FLASK_APP_PORT=${FLASK_APP_PORT:-6664}
    DIRECT_TEST_PORT=${DIRECT_TEST_PORT:-44444}
    
    echo -e "\n${GREEN}======== DEPLOYMENT SUCCESSFUL ========${NC}"
    echo -e "${GREEN}CTF Challenge Deployer is now running!${NC}"
    echo -e "${YELLOW}Access the deployer interface:${NC} http://localhost:$FLASK_APP_PORT"
    echo -e "${YELLOW}Access the challenge directly:${NC} http://localhost:$DIRECT_TEST_PORT"
    echo -e "${BLUE}For more information, check the README.md file.${NC}"
    echo -e "${YELLOW}To stop the service:${NC} $DOCKER_COMPOSE down"
    echo -e "${YELLOW}To view logs:${NC} $DOCKER_COMPOSE logs -f"
}

# Show logs for immediate feedback
show_logs() {
    log_info "Displaying container logs (press Ctrl+C to exit logs)..."
    echo -e "${BLUE}======== CONTAINER LOGS ========${NC}"
    
    $DOCKER_COMPOSE logs -f
}

# Print recommendations for multi-instance setup
print_multi_instance_tips() {
    echo -e "\n${BLUE}======== MULTI-INSTANCE TIPS ========${NC}"
    echo -e "When running multiple deployer instances on the same host, ensure:"
    echo -e "1. Each instance uses a different ${YELLOW}NETWORK_NAME${NC} and ${YELLOW}NETWORK_SUBNET${NC} in .env"
    echo -e "2. Each instance uses a different ${YELLOW}FLASK_APP_PORT${NC} and ${YELLOW}DIRECT_TEST_PORT${NC}"
    echo -e "3. Each instance has non-overlapping ${YELLOW}START_RANGE${NC} and ${YELLOW}STOP_RANGE${NC} port ranges"
    echo -e "4. Use separate data directories for each instance to avoid database conflicts"
}

# Handle clean shutdown
cleanup() {
    echo ""
    log_info "Caught shutdown signal. Exiting gracefully..."
    exit 0
}

# Main function
main() {
    echo -e "${BLUE}======== CTF CHALLENGE DEPLOYER ========${NC}"
    log_info "Starting deployment process..."
    
    # Register signal handlers
    trap cleanup SIGINT SIGTERM
    
    # Run deployment steps
    check_docker
    detect_docker_compose
    check_env_file
    check_network_conflicts
    check_port_conflicts
    safely_cleanup_network
    check_directories
    build_images
    start_containers
    check_services
    check_ports
    print_access_info
    print_multi_instance_tips
    
    # Offer to show logs
    echo ""
    read -p "Do you want to view container logs? (y/n): " show_logs_choice
    if [[ "$show_logs_choice" =~ ^[Yy]$ ]]; then
        show_logs
    fi
    
    log_success "Deployment completed successfully!"
}

# Execute main function
main
