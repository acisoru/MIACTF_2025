#!/bin/bash

# deploy.sh - Deployment script for CTF Challenge Deployer
# Author: Claude
# Date: April 9, 2025

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

# Verify environment file exists
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
}

# Cleanup unused Docker networks
cleanup_networks() {
    log_info "Cleaning up unused Docker networks..."
    
    # List unused networks before pruning
    UNUSED_NETWORKS=$(docker network ls --filter "dangling=true" -q)
    
    if [ -z "$UNUSED_NETWORKS" ]; then
        log_info "No unused networks found."
    else
        NETWORK_COUNT=$(echo "$UNUSED_NETWORKS" | wc -l)
        log_info "Found $NETWORK_COUNT unused networks. Pruning..."
        
        # Prune unused networks
        if docker network prune -f &> /dev/null; then
            log_success "Successfully pruned unused networks."
        else
            log_warning "Failed to prune some networks. Continuing anyway..."
        fi
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
    
    if $DOCKER_COMPOSE up -d; then
        log_success "Docker containers started successfully."
    else
        log_error "Failed to start Docker containers."
        exit 1
    fi
}

# Show logs for immediate feedback
show_logs() {
    log_info "Displaying container logs (press Ctrl+C to exit logs)..."
    echo -e "${BLUE}======== CONTAINER LOGS ========${NC}"
    
    $DOCKER_COMPOSE logs -f
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
    
    # Extract port values from .env file
    FLASK_APP_PORT=$(grep -E "^FLASK_APP_PORT=" .env | cut -d= -f2 | tr -d ' ' | tr -d '"')
    DIRECT_TEST_PORT=$(grep -E "^DIRECT_TEST_PORT=" .env | cut -d= -f2 | tr -d ' ' | tr -d '"')
    
    # If ports aren't set in .env, use defaults
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
    # Extract port values from .env file
    FLASK_APP_PORT=$(grep -E "^FLASK_APP_PORT=" .env | cut -d= -f2 | tr -d ' ' | tr -d '"')
    DIRECT_TEST_PORT=$(grep -E "^DIRECT_TEST_PORT=" .env | cut -d= -f2 | tr -d ' ' | tr -d '"')
    
    # If ports aren't set in .env, use defaults
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
    check_directories
    cleanup_networks
    build_images
    start_containers
    check_services
    check_ports
    print_access_info
    
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
