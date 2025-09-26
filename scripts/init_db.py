#!/usr/bin/env python3
"""
Database initialization script for the AI Bug Hunter framework.

This script creates the database schema, sets up initial data,
and configures the system for first use.
"""

import os
import sys
import logging
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from automation.database import create_tables, drop_tables, engine, SessionLocal
from automation.api_manager import APIManager
from data.schemas import *
import sqlalchemy as sa


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_database_connection():
    """Check if database connection is working."""
    try:
        with engine.connect() as conn:
            result = conn.execute(sa.text("SELECT 1"))
            logger.info("Database connection successful")
            return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False


def create_database_schema():
    """Create all database tables."""
    try:
        logger.info("Creating database schema...")
        create_tables()
        logger.info("Database schema created successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to create database schema: {e}")
        return False


def setup_initial_data():
    """Set up initial data and configurations."""
    try:
        logger.info("Setting up initial data...")
        
        with SessionLocal() as session:
            # Create sample configurations or initial data here
            # For now, we'll just verify the tables exist
            
            # Check if tables were created
            tables = [
                'scan_jobs',
                'findings', 
                'assets'
            ]
            
            for table in tables:
                try:
                    result = session.execute(sa.text(f"SELECT COUNT(*) FROM {table}"))
                    count = result.scalar()
                    logger.info(f"Table '{table}' exists with {count} records")
                except Exception as e:
                    logger.error(f"Table '{table}' check failed: {e}")
                    return False
        
        logger.info("Initial data setup completed")
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup initial data: {e}")
        return False


def setup_directories():
    """Create necessary directories for the application."""
    directories = [
        "logs",
        "logs/audit", 
        "evidence",
        "evidence/screenshots",
        "evidence/http_logs",
        "evidence/pcaps",
        "config",
        "data/wordlists",
        "data/rules",
        "temp"
    ]
    
    for directory in directories:
        dir_path = project_root / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created directory: {directory}")


def setup_api_keys():
    """Setup API key management."""
    try:
        logger.info("Setting up API key management...")
        
        # Initialize API manager (this will load keys from environment)
        api_manager = APIManager()
        
        # Check which services have API keys configured
        services = api_manager.key_store.list_services()
        if services:
            logger.info(f"Configured API services: {', '.join(services)}")
        else:
            logger.warning("No API keys configured. Add them via environment variables:")
            logger.warning("  SHODAN_API_KEY=your_key")
            logger.warning("  VIRUSTOTAL_API_KEY=your_key") 
            logger.warning("  SECURITYTRAILS_API_KEY=your_key")
            logger.warning("  GITHUB_TOKEN=your_token")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to setup API keys: {e}")
        return False


def verify_dependencies():
    """Verify that required dependencies are installed."""
    required_packages = [
        'fastapi',
        'uvicorn', 
        'sqlalchemy',
        'psycopg2',
        'celery',
        'redis',
        'pydantic',
        'httpx',
        'aiohttp',
        'dnspython',
        'playwright',
        'beautifulsoup4',
        'cryptography',
        'structlog'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.error(f"Missing required packages: {', '.join(missing_packages)}")
        logger.error("Install them with: pip install -r requirements.txt")
        return False
    
    logger.info("All required dependencies are installed")
    return True


def setup_environment_file():
    """Create a sample .env file with configuration options."""
    env_file = project_root / ".env.example"
    
    env_content = """# AI Bug Hunter Configuration

# Database Configuration
DATABASE_URL=postgresql://postgres:password@localhost:5432/bug_hunter

# Redis Configuration (for Celery and rate limiting)
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# API Keys (remove .example from filename and add your keys)
SHODAN_API_KEY=your_shodan_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
SECURITYTRAILS_API_KEY=your_securitytrails_api_key_here
GITHUB_TOKEN=your_github_token_here
CENSYS_API_KEY=your_censys_api_key_here
CRUNCHBASE_API_KEY=your_crunchbase_api_key_here

# OpenAI Configuration (for AI features)
OPENAI_API_KEY=your_openai_api_key_here

# Evidence Storage
EVIDENCE_STORAGE_TYPE=local  # or 's3'
EVIDENCE_BASE_PATH=evidence
EVIDENCE_S3_BUCKET=bug-hunter-evidence

# API Key Encryption
API_ENCRYPTION_KEY=generate_with_fernet.generate_key()

# Logging
SQL_DEBUG=false
LOG_LEVEL=INFO

# Security
SECRET_KEY=change_this_in_production
ALLOWED_HOSTS=localhost,127.0.0.1

# Rate Limiting
DEFAULT_RATE_LIMIT=100  # requests per minute
"""
    
    with open(env_file, 'w') as f:
        f.write(env_content)
    
    logger.info(f"Created example environment file: {env_file}")
    logger.info("Copy .env.example to .env and configure your settings")


def main():
    """Main initialization function."""
    logger.info("Starting AI Bug Hunter initialization...")
    
    # Check dependencies first
    if not verify_dependencies():
        logger.error("Dependency check failed. Please install required packages.")
        return False
    
    # Setup directories
    setup_directories()
    
    # Setup environment file
    setup_environment_file()
    
    # Check database connection
    if not check_database_connection():
        logger.error("Database connection failed. Please check your DATABASE_URL.")
        logger.error("Make sure PostgreSQL is running and accessible.")
        return False
    
    # Create database schema
    if not create_database_schema():
        logger.error("Database schema creation failed.")
        return False
    
    # Setup initial data
    if not setup_initial_data():
        logger.error("Initial data setup failed.")
        return False
    
    # Setup API keys
    setup_api_keys()
    
    logger.info("✅ AI Bug Hunter initialization completed successfully!")
    logger.info("")
    logger.info("Next steps:")
    logger.info("1. Copy .env.example to .env and configure your settings")
    logger.info("2. Add your API keys to the .env file")
    logger.info("3. Start the services:")
    logger.info("   - Redis: redis-server")
    logger.info("   - Celery: celery -A automation.orchestrator worker --loglevel=info")
    logger.info("   - API: python ui/api.py")
    logger.info("4. Access the API documentation at http://localhost:8000/docs")
    
    return True


def reset_database():
    """Reset the database (drop and recreate all tables)."""
    logger.warning("This will delete all data in the database!")
    response = input("Are you sure you want to continue? (yes/no): ")
    
    if response.lower() == 'yes':
        logger.info("Dropping all tables...")
        drop_tables()
        logger.info("Recreating tables...")
        create_tables()
        logger.info("Database reset completed")
    else:
        logger.info("Database reset cancelled")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Initialize AI Bug Hunter database and configuration")
    parser.add_argument("--reset", action="store_true", help="Reset database (WARNING: deletes all data)")
    parser.add_argument("--check", action="store_true", help="Check database connection only")
    
    args = parser.parse_args()
    
    if args.reset:
        reset_database()
    elif args.check:
        if check_database_connection():
            logger.info("Database connection is working")
        else:
            logger.error("Database connection failed")
            sys.exit(1)
    else:
        success = main()
        if not success:
            sys.exit(1)
