# AI Bug Hunter Framework

🔍 **An AI-assisted bug-hunting framework that automates high-volume reconnaissance, surfaces high-probability attack paths, runs smart dynamic checks, and produces prioritized findings with reproducible PoCs and recommended mitigations.**

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **PostgreSQL 12+**
- **Redis 6+**
- **Git**

### Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd hunter
```

2. **Set up environment:**
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

3. **Configure environment:**
```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your configuration
nano .env
```

4. **Initialize database:**
```bash
python3 scripts/init_db.py
```

5. **Start services:**
```bash
./scripts/start_services.sh
```

6. **Access the application:**
- **API Documentation:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health

## 📋 Configuration

### Environment Variables

Create a `.env` file with the following configuration:

```bash
# Database Configuration
DATABASE_URL=postgresql://postgres:password@localhost:5432/bug_hunter

# Redis Configuration
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# API Keys (optional but recommended)
SHODAN_API_KEY=your_shodan_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
SECURITYTRAILS_API_KEY=your_securitytrails_api_key_here
GITHUB_TOKEN=your_github_token_here
CENSYS_API_KEY=your_censys_api_key_here

# OpenAI Configuration (for AI features)
OPENAI_API_KEY=your_openai_api_key_here

# Evidence Storage
EVIDENCE_STORAGE_TYPE=local  # or 's3'
EVIDENCE_BASE_PATH=evidence

# Security
API_ENCRYPTION_KEY=generate_with_fernet.generate_key()
```

### API Keys Setup

The framework supports multiple external services for enhanced reconnaissance:

- **Shodan:** Host and service discovery
- **VirusTotal:** Passive DNS and malware analysis
- **SecurityTrails:** Historical DNS data
- **GitHub:** Code repository scanning
- **Censys:** Internet-wide scanning data
- **OpenAI:** AI-powered analysis and PoC generation

## 🏗️ Architecture

### Core Components

```
hunter/
├── automation/          # Orchestration and core services
│   ├── orchestrator.py  # Job scheduling and workflow management
│   ├── database.py      # Database models and repositories
│   ├── api_manager.py   # API key management and rate limiting
│   ├── ai_services.py   # LLM and embedding services
│   └── logging_config.py # Audit logging and evidence storage
├── recon/              # Reconnaissance modules
│   ├── collectors.py   # Data collection from various sources
│   └── tasks.py        # Celery tasks for distributed recon
├── analysis/           # Content discovery and app analysis
│   └── tasks.py        # Web application analysis tasks
├── fuzz/               # Vulnerability scanning and fuzzing
│   └── tasks.py        # Automated vulnerability detection
├── ui/                 # Web interface
│   └── api.py          # FastAPI REST API
├── data/               # Data models and schemas
│   └── schemas.py      # Pydantic models for all entities
├── docs/               # Documentation
│   └── legal-ethics-policy.md # Legal and ethical guidelines
└── scripts/            # Utility scripts
    ├── init_db.py      # Database initialization
    ├── start_services.sh # Service startup script
    └── stop_services.sh  # Service shutdown script
```

### Data Flow

1. **Job Submission** → API receives scan requests
2. **Task Distribution** → Celery distributes work to workers
3. **Data Collection** → Collectors gather information from various sources
4. **Analysis** → AI services analyze findings and generate insights
5. **Storage** → Results stored in PostgreSQL with evidence in file system
6. **Reporting** → Dashboard and API provide access to findings

## 🔧 Usage

### Starting a Reconnaissance Scan

```bash
# Using curl
curl -X POST "http://localhost:8000/scans" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "scan_type": "recon",
    "priority": 8
  }'
```

### Running a Full Workflow

```bash
# Start comprehensive reconnaissance
curl -X POST "http://localhost:8000/workflows/recon?target=example.com"

# Start vulnerability assessment
curl -X POST "http://localhost:8000/workflows/vulnerability-assessment?target=example.com"
```

### Viewing Results

```bash
# List all scans
curl "http://localhost:8000/scans"

# Get scan status
curl "http://localhost:8000/scans/{job_id}"

# List findings
curl "http://localhost:8000/findings"

# Get dashboard statistics
curl "http://localhost:8000/dashboard/stats"
```

## 🛡️ Security & Ethics

### Legal Compliance

**⚠️ IMPORTANT:** This framework is designed for authorized security testing only. Before using:

1. **Read the [Legal & Ethics Policy](docs/legal-ethics-policy.md)**
2. **Obtain written authorization** for all targets
3. **Respect scope limitations** and out-of-scope rules
4. **Follow responsible disclosure** practices

### Safe Usage Guidelines

- ✅ **Only test systems you own or have explicit permission to test**
- ✅ **Implement reasonable rate limiting** to avoid service disruption
- ✅ **Document all activities** for audit purposes
- ✅ **Report findings responsibly** to appropriate parties
- ❌ **Never test without authorization**
- ❌ **Never access or modify sensitive data**
- ❌ **Never perform destructive actions**

## 🔍 Features

### Reconnaissance Capabilities

- **Certificate Transparency Logs** - Subdomain discovery via CT logs
- **Passive DNS** - Historical DNS data analysis
- **Shodan Integration** - Internet-wide host discovery
- **GitHub Dorking** - Code repository scanning
- **Wayback Machine** - Historical content analysis
- **Technology Fingerprinting** - Framework and service identification

### Vulnerability Detection

- **SQL Injection** - Automated SQLi detection with error-based analysis
- **Cross-Site Scripting (XSS)** - Reflected and stored XSS detection
- **Server-Side Request Forgery (SSRF)** - Internal service probing
- **Directory Traversal** - File inclusion vulnerability testing
- **Information Disclosure** - Sensitive file and configuration exposure
- **Security Misconfigurations** - Missing security headers and controls

### AI-Powered Analysis

- **Intelligent Triage** - AI-assisted finding prioritization
- **PoC Generation** - Automated proof-of-concept creation
- **Vulnerability Analysis** - LLM-powered security assessment
- **Report Summarization** - Natural language finding summaries

### Evidence Management

- **Screenshot Capture** - Automated web application screenshots
- **Request/Response Logging** - Complete HTTP transaction recording
- **Audit Trail** - Immutable activity logging
- **Evidence Storage** - Secure file storage with integrity verification

## 📊 Dashboard & Reporting

### Web Interface Features

- **Real-time Scan Monitoring** - Live status updates
- **Finding Management** - Triage, assignment, and tracking
- **Asset Inventory** - Comprehensive asset discovery view
- **Evidence Viewer** - Integrated evidence examination
- **Export Capabilities** - PDF and JSON report generation

### API Endpoints

- `GET /health` - System health check
- `POST /scans` - Submit new scan job
- `GET /scans/{id}` - Get scan status
- `GET /findings` - List security findings
- `POST /findings/{id}/triage` - Triage findings
- `GET /assets` - List discovered assets
- `GET /dashboard/stats` - System statistics

## 🔧 Development

### Running in Development Mode

```bash
# Start individual components
redis-server
celery -A automation.orchestrator worker --loglevel=info
python3 -m uvicorn ui.api:app --reload --host 0.0.0.0 --port 8000
```

### Testing

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html
```

### Adding New Collectors

1. Create collector class in `recon/collectors.py`
2. Implement `collect()` method
3. Add to `ReconOrchestrator`
4. Create corresponding Celery task in `recon/tasks.py`

### Database Migrations

```bash
# Reset database (WARNING: deletes all data)
python3 scripts/init_db.py --reset

# Check database connection
python3 scripts/init_db.py --check
```

## 🚦 Service Management

### Starting Services

```bash
./scripts/start_services.sh
```

### Stopping Services

```bash
./scripts/stop_services.sh
```

### Service Status

```bash
# Check individual services
redis-cli ping
celery -A automation.orchestrator inspect ping
curl http://localhost:8000/health
```

## 📚 Documentation

- **[Legal & Ethics Policy](docs/legal-ethics-policy.md)** - Legal compliance and ethical guidelines
- **[API Documentation](http://localhost:8000/docs)** - Interactive API documentation
- **[Data Schemas](data/schemas.py)** - Complete data model documentation

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

### Development Guidelines

- Follow PEP 8 style guidelines
- Add comprehensive docstrings
- Include unit tests for new features
- Update documentation as needed
- Ensure legal and ethical compliance

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The developers assume no liability for misuse of this software.

## 🆘 Support

- **Issues:** [GitHub Issues](https://github.com/your-repo/issues)
- **Documentation:** [Project Wiki](https://github.com/your-repo/wiki)
- **Security:** Report security issues privately to security@yourproject.com

---

**Happy Bug Hunting! 🐛🔍**
