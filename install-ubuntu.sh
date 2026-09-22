#!/bin/bash
#
# CloudWatch Sentinel - Ubuntu Quick Install Script
# 
# This script automates the installation and setup of CloudWatch Sentinel
# on Ubuntu/Debian Linux systems.
#
# Usage:
#   sudo bash install.sh
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_DIR="/opt/cloudwatch-sentinel"
APP_USER="ubuntu"
VENV_PATH="$APP_DIR/venv"
MYSQL_DB="cloudwatch_sentinel"
MYSQL_USER="sentinel"

# Helper functions
print_status() {
    echo -e "${BLUE}==>${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

echo ""
echo "========================================="
echo "  CloudWatch Sentinel Installation"
echo "========================================="
echo ""

# Check Ubuntu version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    print_status "Detected OS: $NAME $VERSION"
else
    print_error "Cannot detect OS version"
    exit 1
fi

# Step 1: System Update
print_status "Updating system packages..."
apt update -qq
apt upgrade -y -qq
print_success "System updated"

# Step 2: Install Python
print_status "Installing Python 3 and pip..."
apt install -y python3 python3-pip python3-venv python3-dev build-essential
print_success "Python installed: $(python3 --version)"

# Step 3: Install MySQL
print_status "Checking MySQL installation..."
if ! command -v mysql &> /dev/null; then
    print_status "Installing MySQL Server..."
    apt install -y mysql-server
    systemctl start mysql
    systemctl enable mysql
    print_success "MySQL installed and started"
else
    print_success "MySQL already installed"
fi

# Step 4: Configure MySQL
print_status "Setting up MySQL database..."
read -sp "Enter MySQL root password (press Enter if none set): " MYSQL_ROOT_PASSWORD
echo ""
read -sp "Enter new password for CloudWatch Sentinel database user: " MYSQL_SENTINEL_PASSWORD
echo ""

# Create database and user
if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
    mysql -e "CREATE DATABASE IF NOT EXISTS $MYSQL_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null || true
    mysql -e "CREATE USER IF NOT EXISTS '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_SENTINEL_PASSWORD';" 2>/dev/null || true
    mysql -e "GRANT ALL PRIVILEGES ON ${MYSQL_DB}.* TO '$MYSQL_USER'@'localhost';" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
else
    mysql -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS $MYSQL_DB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null || true
    mysql -p"$MYSQL_ROOT_PASSWORD" -e "CREATE USER IF NOT EXISTS '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_SENTINEL_PASSWORD';" 2>/dev/null || true
    mysql -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON ${MYSQL_DB}.* TO '$MYSQL_USER'@'localhost';" 2>/dev/null || true
    mysql -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;" 2>/dev/null || true
fi
print_success "MySQL database configured"

# Step 5: Create application directory
print_status "Setting up application directory..."
mkdir -p "$APP_DIR"
cd "$APP_DIR"

# Copy files (assume script is run from project directory)
if [ -f "$(dirname $0)/requirements.txt" ]; then
    cp -r "$(dirname $0)"/* "$APP_DIR/" 2>/dev/null || true
    print_success "Application files copied"
else
    print_warning "Please copy application files to $APP_DIR manually"
fi

# Step 6: Set ownership
chown -R $APP_USER:$APP_USER "$APP_DIR"
print_success "Ownership set to $APP_USER"

# Step 7: Create virtual environment
print_status "Creating Python virtual environment..."
sudo -u $APP_USER python3 -m venv "$VENV_PATH"
print_success "Virtual environment created"

# Step 8: Install Python dependencies
print_status "Installing Python dependencies..."
sudo -u $APP_USER "$VENV_PATH/bin/pip" install --quiet --upgrade pip
sudo -u $APP_USER "$VENV_PATH/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
print_success "Dependencies installed"

# Step 9: Import database schema
if [ -f "$APP_DIR/schema.sql" ]; then
    print_status "Importing database schema..."
    if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
        mysql -u $MYSQL_USER -p"$MYSQL_SENTINEL_PASSWORD" $MYSQL_DB < "$APP_DIR/schema.sql"
    else
        mysql -p"$MYSQL_ROOT_PASSWORD" $MYSQL_DB < "$APP_DIR/schema.sql"
    fi
    print_success "Database schema imported"
else
    print_warning "schema.sql not found - skipping database import"
fi

# Step 10: Create .env file if it doesn't exist
if [ ! -f "$APP_DIR/.env" ]; then
    print_status "Creating .env configuration file..."
    
    read -p "Enter AWS Access Key ID: " AWS_KEY
    read -sp "Enter AWS Secret Access Key: " AWS_SECRET
    echo ""
    read -p "Enter AWS Region (default: us-east-1): " AWS_REGION
    AWS_REGION=${AWS_REGION:-us-east-1}
    
    read -p "Enter OpenAI API Key: " OPENAI_KEY
    
    read -p "Enter SMTP Host (default: smtp.gmail.com): " SMTP_HOST
    SMTP_HOST=${SMTP_HOST:-smtp.gmail.com}
    read -p "Enter SMTP Port (default: 587): " SMTP_PORT
    SMTP_PORT=${SMTP_PORT:-587}
    read -p "Enter SMTP Username/Email: " SMTP_USER
    read -sp "Enter SMTP Password: " SMTP_PASSWORD
    echo ""
    read -p "Enter Alert Recipient Email: " ALERT_EMAIL
    
    cat > "$APP_DIR/.env" << EOF
# AWS Credentials
AWS_ACCESS_KEY_ID=$AWS_KEY
AWS_SECRET_ACCESS_KEY=$AWS_SECRET
AWS_DEFAULT_REGION=$AWS_REGION

# MySQL Configuration
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_USER=$MYSQL_USER
MYSQL_PASSWORD=$MYSQL_SENTINEL_PASSWORD
MYSQL_DATABASE=$MYSQL_DB

# OpenAI API
OPENAI_API_KEY=$OPENAI_KEY
OPENAI_MODEL=gpt-4o-mini

# Email Configuration
SMTP_HOST=$SMTP_HOST
SMTP_PORT=$SMTP_PORT
SMTP_USER=$SMTP_USER
SMTP_PASSWORD=$SMTP_PASSWORD
ALERT_EMAIL_FROM=$SMTP_USER
ALERT_EMAIL_TO=$ALERT_EMAIL
EOF
    
    chmod 600 "$APP_DIR/.env"
    chown $APP_USER:$APP_USER "$APP_DIR/.env"
    print_success ".env file created"
else
    print_warning ".env file already exists - skipping"
fi

# Step 11: Test installation
print_status "Testing installation..."
cd "$APP_DIR"

# Test email
print_status "Testing email configuration..."
if sudo -u $APP_USER "$VENV_PATH/bin/python" scheduler.py --test; then
    print_success "Email configuration is working"
else
    print_warning "Email test failed - please check SMTP settings"
fi

# Step 12: Install systemd services
print_status "Installing systemd services..."

if [ -f "$APP_DIR/cloudwatch-sentinel-scheduler.service" ]; then
    cp "$APP_DIR/cloudwatch-sentinel-scheduler.service" /etc/systemd/system/
    print_success "Scheduler service installed"
fi

if [ -f "$APP_DIR/cloudwatch-sentinel-scheduler.timer" ]; then
    cp "$APP_DIR/cloudwatch-sentinel-scheduler.timer" /etc/systemd/system/
    print_success "Scheduler timer installed"
fi

if [ -f "$APP_DIR/cloudwatch-sentinel.service" ]; then
    cp "$APP_DIR/cloudwatch-sentinel.service" /etc/systemd/system/
    print_success "Dashboard service installed"
fi

systemctl daemon-reload
print_success "Systemd reloaded"

# Step 13: Enable and start services
print_status "Enabling services..."

# Ask which services to enable
echo ""
echo "Which services would you like to enable?"
read -p "Enable hourly scheduler (timer)? [Y/n]: " ENABLE_TIMER
read -p "Enable Streamlit dashboard? [Y/n]: " ENABLE_DASHBOARD

if [[ ! $ENABLE_TIMER =~ ^[Nn]$ ]]; then
    systemctl enable cloudwatch-sentinel-scheduler.timer
    systemctl start cloudwatch-sentinel-scheduler.timer
    print_success "Scheduler timer enabled and started"
    
    # Show next run time
    systemctl list-timers cloudwatch-sentinel-scheduler.timer --no-pager
fi

if [[ ! $ENABLE_DASHBOARD =~ ^[Nn]$ ]]; then
    systemctl enable cloudwatch-sentinel.service
    systemctl start cloudwatch-sentinel.service
    print_success "Dashboard service enabled and started"
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    echo ""
    print_success "Dashboard available at: http://$SERVER_IP:8501"
fi

# Installation complete
echo ""
echo "========================================="
echo -e "${GREEN}Installation Complete!${NC}"
echo "========================================="
echo ""
print_status "Next steps:"
echo "  1. Edit configuration: sudo nano $APP_DIR/.env"
echo "  2. View scheduler logs: sudo journalctl -u cloudwatch-sentinel-scheduler -f"
echo "  3. View dashboard logs: sudo journalctl -u cloudwatch-sentinel -f"
echo "  4. Run manual analysis: cd $APP_DIR && source venv/bin/activate && python scheduler.py"
echo "  5. Check timer status: systemctl status cloudwatch-sentinel-scheduler.timer"
echo ""
print_status "Documentation:"
echo "  - Linux Deployment: $APP_DIR/LINUX_DEPLOYMENT.md"
echo "  - Scheduler Setup: $APP_DIR/SCHEDULER_SETUP.md"
echo ""
print_warning "IMPORTANT: Secure your .env file - it contains sensitive credentials!"
echo ""
