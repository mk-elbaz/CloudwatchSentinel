from openai import OpenAI
from typing import List
from src.models import Incident
import json
import os
import re


class LogAnalyzer:
    """Analyzes logs using OpenAI API for semantic understanding."""
    
    # Error patterns that indicate real errors worth analyzing
    ERROR_PATTERNS = [
        r'Exception',
        r'Error:',
        r'ERROR',
        r'FATAL',
        r'CRITICAL',
        r'\bfailed\b',
        r'\bfailure\b',
        r'stack trace',
        r'Traceback',
        r'at [a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\(',  # Stack trace line
        r'\b5[0-9]{2}\b',  # 5xx HTTP codes
        r'timeout',
        r'timed out',
        r'OutOfMemory',
        r'OOM',
        r'Connection refused',
        r'Connection reset',
        r'Cannot connect',
        r'Database connection failed',
        r'Access denied',
        r'Permission denied',
        r'Unauthorized',
    ]
    
    @staticmethod
    def contains_real_errors(logs: str) -> bool:
        """
        Check if logs contain actual error patterns worth analyzing with AI.
        This prevents expensive API calls for normal/info logs.
        
        Args:
            logs: Raw log text to check
            
        Returns:
            True if logs contain error patterns, False otherwise
        """
        if not logs or not logs.strip():
            return False
        
        # Check for any error pattern
        for pattern in LogAnalyzer.ERROR_PATTERNS:
            if re.search(pattern, logs, re.IGNORECASE | re.MULTILINE):
                return True
        
        return False
    
    def __init__(self):
        """
        Initialize OpenAI client.
        API key should be in .env file: OPENAI_API_KEY=sk-...
        """
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        self.client = OpenAI(api_key=api_key)
        self.model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
    
    def analyze_logs(
        self, 
        logs: str, 
        log_group: str, 
        noise_patterns: List[str]
    ) -> List[Incident]:
        """
        Analyze error logs using OpenAI API.
        
        IMPORTANT: Only call this when logs contain real errors (exceptions, failures, etc.).
        Use contains_real_errors() first to avoid unnecessary API calls.
        
        Args:
            logs: Raw log text to analyze (should contain actual errors)
            log_group: Name of the CloudWatch log group
            noise_patterns: List of patterns to ignore
            
        Returns:
            List of Incident objects (excluding NOISE severity)
        """
        
        if not logs.strip():
            return []
        
        noise_section = "\n".join([f"- {p}" for p in noise_patterns]) if noise_patterns else "None defined"
        
        system_prompt = f"""You are a Senior SRE analyzing production logs from AWS CloudWatch.

IGNORE these patterns (known noise):
{noise_section}
- Standard startup messages
- Graceful connection closures
- Deprecation warnings we can't fix yet
- Health check requests
- Normal Lambda cold starts

PRIORITIZE (in order of severity):
1. Stack traces with exceptions
2. Database errors (connection failures, integrity constraints, query failures, SQLSTATE errors)
3. Out of Memory (OOM) errors
4. Timeouts (Lambda/API Gateway/Database)
5. 5xx HTTP status codes
6. Authentication/Authorization failures
7. FATAL, ERROR, or CRITICAL level logs

GROUPING RULES:
- If multiple logs describe the SAME error, create ONE incident
- Group by root cause, not by timestamp
- Include the most relevant log lines (max 5) in raw_logs

OUTPUT FORMAT:
Return a JSON object with an "incidents" array. Each incident MUST have:
- summary: One sentence, clear and actionable (no jargon)
- severity: "CRITICAL" | "WARNING" | "INFO" | "NOISE"
- root_cause: Technical diagnosis of what failed and why
- recommendation: Specific action to fix (e.g., "Increase Lambda memory to 512MB" or "Check RDS connection limits")
- affected_service: Service name if identifiable from log stream name
- raw_logs: Array of the most relevant log lines (max 5)

SEVERITY GUIDELINES:
- CRITICAL: Service down, data loss risk, database errors, security breach, exceptions, stack traces
- WARNING: Degraded performance, approaching limits, intermittent failures, deprecation notices
- INFO: Notable events that may need attention later, informational messages
- NOISE: Known issues, expected behavior, can be ignored

IMPORTANT: Database integrity constraint violations, SQL errors, and production.ERROR logs are CRITICAL."""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze these logs from '{log_group}':\n\n{logs[:50000]}"}  # Limit context to ~50k chars
                ],
                response_format={"type": "json_object"},
                temperature=0  # Deterministic output
            )
            
            content = response.choices[0].message.content
            data = json.loads(content)
            
            # Parse into Pydantic models
            incidents = []
            for item in data.get('incidents', []):
                try:
                    incident = Incident(
                        log_group=log_group,
                        summary=item.get('summary', 'Unknown error'),
                        severity=item.get('severity', 'WARNING'),
                        root_cause=item.get('root_cause', 'Unknown'),
                        recommendation=item.get('recommendation', 'Investigate further'),
                        affected_service=item.get('affected_service', 'Unknown'),
                        raw_logs=item.get('raw_logs', [])[:5]  # Limit to 5 logs
                    )
                    
                    # Filter out NOISE - we don't need to store these
                    if incident.severity != "NOISE":
                        incidents.append(incident)
                        
                except Exception as e:
                    print(f"Failed to parse incident: {e}")
                    continue
            
            return incidents
            
        except json.JSONDecodeError as e:
            print(f"Failed to parse OpenAI response as JSON: {e}")
            return []
        except Exception as e:
            print(f"Analysis error: {e}")
            return []
    
    def get_quick_summary(self, logs: str) -> str:
        """
        Get a quick one-line summary of logs without full analysis.
        Useful for preview in UI.
        """
        if not logs.strip():
            return "No logs to analyze"
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a log analyzer. Provide a one-sentence summary of the main issues in these logs. Be concise."
                    },
                    {
                        "role": "user", 
                        "content": f"Summarize these logs:\n\n{logs[:10000]}"
                    }
                ],
                max_tokens=100,
                temperature=0
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            return f"Could not generate summary: {e}"
