import pymysql
from contextlib import contextmanager
from typing import List, Optional
from src.models import Incident, AnalysisRun
import json
import os


class Database:
    """MySQL database operations for CloudWatch Sentinel."""
    
    def __init__(self):
        self.config = {
            'host': os.getenv('MYSQL_HOST', 'localhost'),
            'port': int(os.getenv('MYSQL_PORT', 3306)),
            'user': os.getenv('MYSQL_USER', 'root'),
            'password': os.getenv('MYSQL_PASSWORD', ''),
            'database': os.getenv('MYSQL_DATABASE', 'cloudwatch_sentinel'),
            'charset': 'utf8mb4'
        }
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = None
        try:
            conn = pymysql.connect(**self.config)
            yield conn
        except Exception as e:
            print(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def _dict_cursor(self, conn):
        """Get a dictionary cursor."""
        return conn.cursor(pymysql.cursors.DictCursor)
    
    def test_connection(self) -> bool:
        """Test database connectivity."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                cursor.fetchone()
                return True
        except Exception as e:
            print(f"Database connection test failed: {e}")
            return False
    
    def save_incident(self, incident: Incident) -> bool:
        """
        Insert a new incident or update an existing unresolved one (deduplication).
        Returns True if successful, but note it might have been an update.
        """
        success, is_new = self.save_incident_with_status(incident)
        return success

    def save_incident_with_status(self, incident: Incident) -> tuple:
        """
        Save incident and return (success, is_new).
        """
        # Check for existing unresolved incident with same summary and log group
        check_query = """
            SELECT id FROM incidents 
            WHERE summary = %s AND log_group = %s AND resolved = FALSE
            ORDER BY timestamp DESC LIMIT 1
        """
        
        insert_query = """
            INSERT INTO incidents 
            (id, timestamp, log_group, severity, summary, root_cause, 
             recommendation, affected_service, raw_logs, occurrence_count, last_seen)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        update_query = """
            UPDATE incidents 
            SET occurrence_count = occurrence_count + 1,
                last_seen = %s,
                severity = %s,
                raw_logs = %s
            WHERE id = %s
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Deduplication check
                cursor.execute(check_query, (incident.summary, incident.log_group))
                existing = cursor.fetchone()
                
                if existing:
                    # Update existing incident
                    existing_id = existing[0]
                    cursor.execute(update_query, (
                        incident.timestamp,
                        incident.severity,
                        json.dumps(incident.raw_logs),
                        existing_id
                    ))
                    conn.commit()
                    print(f"🔄 Deduplicated incident: {incident.summary} (ID: {existing_id})")
                    return True, False
                else:
                    # Insert new incident
                    cursor.execute(insert_query, (
                        incident.id,
                        incident.timestamp,
                        incident.log_group,
                        incident.severity,
                        incident.summary,
                        incident.root_cause,
                        incident.recommendation,
                        incident.affected_service,
                        json.dumps(incident.raw_logs),
                        incident.occurrence_count,
                        incident.timestamp
                    ))
                    conn.commit()
                    return True, True
        except Exception as e:
            print(f"Failed to save incident: {e}")
            return False, False
    
    def get_recent_incidents(
        self, 
        hours: int = 24, 
        severity: Optional[str] = None,
        log_group: Optional[str] = None
    ) -> List[dict]:
        """Fetch recent incidents with optional filters."""
        query = """
            SELECT id, timestamp, log_group, severity, summary, root_cause, 
                   recommendation, affected_service, resolved, created_at, raw_logs,
                   occurrence_count, last_seen
            FROM incidents 
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL %s HOUR)
        """
        params = [hours]
        
        if severity:
            query += " AND severity = %s"
            params.append(severity)
        
        if log_group:
            query += " AND log_group = %s"
            params.append(log_group)
        
        query += " ORDER BY timestamp DESC LIMIT 100"
        
        try:
            with self.get_connection() as conn:
                cursor = self._dict_cursor(conn)
                cursor.execute(query, params)
                return cursor.fetchall()
        except Exception as e:
            print(f"Failed to fetch incidents: {e}")
            return []
    
    def mark_resolved(self, incident_id: str) -> bool:
        """Mark an incident as resolved."""
        query = "UPDATE incidents SET resolved = TRUE WHERE id = %s"
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (incident_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Failed to mark resolved: {e}")
            return False
    
    def save_analysis_run(self, run: AnalysisRun) -> bool:
        """Store metadata about an analysis run."""
        query = """
            INSERT INTO analysis_runs
            (id, log_group, start_time, end_time, total_logs, 
             incidents_found, duration_seconds)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (
                    run.id,
                    run.log_group,
                    run.start_time,
                    run.end_time,
                    run.total_logs,
                    run.incidents_found,
                    run.duration_seconds
                ))
                conn.commit()
                return True
        except Exception as e:
            print(f"Failed to save analysis run: {e}")
            return False
    
    def get_noise_patterns(self, log_group: Optional[str] = None) -> List[str]:
        """
        Retrieve active noise patterns for filtering.
        
        Args:
            log_group: Optional log group name to get specific patterns
            
        Returns:
            List of noise pattern strings
        """
        query = "SELECT pattern FROM noise_patterns WHERE active = TRUE"
        params = []
        
        if log_group:
            query += " AND (log_group = %s OR log_group IS NULL)"
            params.append(log_group)
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                return [row[0] for row in cursor.fetchall()]
        except Exception as e:
            print(f"Failed to fetch noise patterns: {e}")
    def get_noise_patterns_detailed(self) -> List[dict]:
        """Retrieve all noise patterns with full details for management."""
        query = "SELECT id, pattern, log_group, description, active, created_at FROM noise_patterns ORDER BY created_at DESC"
        
        try:
            with self.get_connection() as conn:
                cursor = self._dict_cursor(conn)
                cursor.execute(query)
                return cursor.fetchall()
        except Exception as e:
            print(f"Failed to fetch detailed noise patterns: {e}")
            return []

    def add_noise_pattern(self, pattern: str, log_group: Optional[str] = None, description: str = "") -> bool:
        """Add a new noise pattern."""
        query = """
            INSERT INTO noise_patterns (pattern, log_group, description)
            VALUES (%s, %s, %s)
        """
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (pattern, log_group, description))
                conn.commit()
                return True
        except Exception as e:
            print(f"Failed to add noise pattern: {e}")
            return False
    
    def get_stats(self) -> dict:
        """Get overall statistics for dashboard."""
        query = """
            SELECT 
                COUNT(*) as total_incidents,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'WARNING' THEN 1 ELSE 0 END) as warnings,
                SUM(CASE WHEN severity = 'INFO' THEN 1 ELSE 0 END) as info,
                SUM(CASE WHEN resolved = FALSE THEN 1 ELSE 0 END) as unresolved
            FROM incidents
            WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """
        
        try:
            with self.get_connection() as conn:
                cursor = self._dict_cursor(conn)
                cursor.execute(query)
                result = cursor.fetchone()
                # Handle None values
                return {
                    'total_incidents': result['total_incidents'] or 0,
                    'critical': result['critical'] or 0,
                    'warnings': result['warnings'] or 0,
                    'info': result['info'] or 0,
                    'unresolved': result['unresolved'] or 0
                }
        except Exception as e:
            print(f"Failed to fetch stats: {e}")
            return {
                'total_incidents': 0,
                'critical': 0,
                'warnings': 0,
                'info': 0,
                'unresolved': 0
            }
    
    def delete_old_incidents(self, days: int = 90) -> int:
        """Delete incidents older than specified days. Returns count deleted."""
        query = "DELETE FROM incidents WHERE timestamp < DATE_SUB(NOW(), INTERVAL %s DAY)"
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (days,))
                conn.commit()
                return cursor.rowcount
        except Exception as e:
            print(f"Failed to delete old incidents: {e}")
            return 0
