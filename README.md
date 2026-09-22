# CloudWatch AI Sentinel 🛡️

**CloudWatch AI Sentinel** is an intelligent, AI-powered AWS monitoring and security agent. It goes beyond traditional alert systems by using Large Language Models (LLMs) to perform semantic analysis on CloudWatch logs, providing human-readable diagnoses and actionable remediation steps for infrastructure incidents.


## 🚀 The "Why"

Traditional CloudWatch alarms tell you *that* something is wrong, but often they don't tell you *what* or *why*. This project was born from the need to automate the "Investigative" phase of SRE work—extracting logs, identifying stack traces, and suggesting fixes—into a single automated workflow.

## ✨ Core Modules & Capabilities

### 🧠 AI-Powered Log Analysis
*   **Semantic Understanding**: Goes beyond keyword matching to understand the *context* of errors using LLMs.
*   **Intelligent Grouping**: Automatically deduplicates similar errors across thousands of log lines into a single "Incident."
*   **Actionable Remediation**: Each alert comes with a specific "Recommendation" (e.g., "Increase Lambda memory" or "Fix SQLSTATE 23000").
*   **Noise Filtering**: Learns your "normal" logs to suppress false positives like standard depreciation warnings or health checks.

### 🔒 Security & Compliance
*   **Security Analyzer**: Scans for overly permissive Security Group rules (SSH/RDP open to 0.0.0.0/0), public S3 buckets, and IAM wildcard permissions (`*:*`).
*   **Compliance Checker**: Audits your infrastructure against the **AWS Well-Architected Framework** pillars (Reliability, Security, etc.).
*   **Tagging Enforcement**: Validates that resources follow organizational tagging standards for cost allocation and ownership.

### 📈 Performance & Capacity
*   **Performance Insights**: Identifies Lambda cold start patterns, predicts timeout risks, and flags over-provisioned RDS/EC2 instances to save costs.
*   **Quota Monitor**: Visual tracking of AWS service limits (EC2 instances, Lambda concurrency) with proactive alerts at 80% and 90% utilization.
*   **Health Dashboard**: Aggregates health status from CloudWatch Alarms, EC2 instance status checks, and RDS availability into a single "Health Score."

### 🔄 Disaster Recovery
*   **Backup Analyzer**: Inventories RDS snapshots, S3 bucket versioning, and EC2 AMIs to calculate a "DR Readiness Score."
*   **Stale Asset Detection**: Flags backups older than your RPO (Recovery Point Objective) or unencrypted backup vaults.

### 📧 Enterprise Alerting
*   **Rich HTML Alerts**: Professional email notifications with deep links to affected log groups and AI-generated root cause summaries.
*   **Operational Sync**: Perfect for Slack/Email integration to keep the whole team informed.


## 🛠️ Tech Stack

- **Core**: Python 3.10+
- **AWS Integration**: Boto3 (CloudWatch, EC2, S3, RDS, IAM, Cost Explorer, etc.)
- **AI Engine**: OpenAI API (GPT-4o-mini / GPT-4o)
- **Database**: MySQL 8.0 (Incident storage & history)
- **Frontend**: Streamlit (Modern, interactive dashboard)
- **Infrastructure**: Docker & Docker Compose

## 📦 Getting Started

### Prerequisites

- Python 3.10+
- MySQL 8.0 (or Docker)
- AWS Credentials (IAM user with read access to CloudWatch and resources)
- OpenAI API Key

### Quick Start

1. **Clone the repository**:

   ```bash
   git clone https://github.com/mk-elbaz/CloudwatchSentinel.git
   cd CloudwatchSentinel
   ```
2. **Setup environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. **Configure your `.env`**:

   ```bash
   cp .env.example .env
   # Edit .env with your AWS, OpenAI, and MySQL details
   ```
4. **Initialize Database**:

   ```bash
   mysql -u root -p < schema.sql
   ```
5. **Run the Dashboard**:

   ```bash
   streamlit run dashboard.py
   ```
6. **Start the Scheduler**:

   ```bash
   # Run once
   python scheduler.py --all-features

   # Run as a background daemon (hourly)
   python scheduler.py --daemon --interval 60 --all-features
   ```

## 🛡️ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

*Disclaimer: This tool uses AI to analyze logs and provide recommendations. Always verify recommendations before applying them to production environments.*
