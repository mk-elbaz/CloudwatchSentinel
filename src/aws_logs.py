import boto3
from datetime import datetime, timedelta
from typing import List, Optional
import os


class CloudWatchCollector:
    """Fetches logs from AWS CloudWatch using boto3."""
    
    def __init__(self):
        """
        Initialize boto3 client with credentials from environment or AWS CLI config.
        Connects to AWS CloudWatch from your local VM.
        
        Credentials are loaded from (in order):
        1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        2. ~/.aws/credentials file (from aws configure)
        3. IAM role (if running on EC2)
        """
        self.client = boto3.client(
            'logs',
            region_name=os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        )
    
    def test_connection(self) -> bool:
        """Test if AWS credentials are valid."""
        try:
            self.client.describe_log_groups(limit=1)
            return True
        except Exception as e:
            print(f"AWS Connection Failed: {e}")
            return False
    
    def list_log_groups(self, prefix: Optional[str] = None) -> List[str]:
        """List available log groups for UI dropdown."""
        try:
            kwargs = {'limit': 50}
            if prefix:
                kwargs['logGroupNamePrefix'] = prefix
            
            response = self.client.describe_log_groups(**kwargs)
            return [lg['logGroupName'] for lg in response.get('logGroups', [])]
        except Exception as e:
            print(f"Failed to list log groups: {e}")
            return []
    
    def fetch_recent_error_logs(
        self, 
        log_group_name: str, 
        minutes: int = 15
    ) -> str:
        """
        Fetches log events from CloudWatch that contain error patterns.
        Handles pagination for large result sets.
        
        Args:
            log_group_name: Full path like /aws/lambda/my-function
            minutes: Time window to search (default 15 minutes)
            
        Returns:
            Formatted string of log entries, or error message
        """
        start_time = int((datetime.now() - timedelta(minutes=minutes)).timestamp() * 1000)
        
        try:
            events = []
            next_token = None
            max_iterations = 10  # Safety limit to prevent infinite loops
            iteration = 0
            
            # Pagination loop to get all matching logs
            while iteration < max_iterations:
                kwargs = {
                    'logGroupName': log_group_name,
                    'startTime': start_time,
                    'filterPattern': '?Error ?Exception ?fail ?timeout ?FATAL ?error ?ERROR',
                    'limit': 100
                }
                
                if next_token:
                    kwargs['nextToken'] = next_token
                
                response = self.client.filter_log_events(**kwargs)
                events.extend(response.get('events', []))
                
                next_token = response.get('nextToken')
                if not next_token:
                    break
                
                iteration += 1
            
            if not events:
                return ""
            
            # Format logs for the LLM
            logs = []
            for event in events:
                timestamp = datetime.fromtimestamp(event['timestamp'] / 1000)
                # Include log stream name for better context
                stream_name = event.get('logStreamName', 'unknown')
                logs.append(f"[{timestamp}] [{stream_name}] {event['message']}")
            
            return "\n".join(logs)
            
        except self.client.exceptions.ResourceNotFoundException:
            return f"Error: Log group '{log_group_name}' not found"
        except self.client.exceptions.InvalidParameterException as e:
            return f"Error: Invalid parameters - {str(e)}"
        except Exception as e:
            return f"Failed to fetch logs: {str(e)}"
    
    def fetch_recent_logs(
        self, 
        log_group_name: str, 
        minutes: int = 15,
        limit: int = 500,
        filter_text: Optional[str] = None
    ) -> List[dict]:
        """
        Fetches all recent log events (not just errors) from CloudWatch.
        Returns structured data for UI display.
        
        Performance optimized: fetches from recent log streams first to avoid
        scanning thousands of old logs.
        
        Args:
            log_group_name: Full path like /aws/lambda/my-function
            minutes: Time window to search
            limit: Maximum number of log entries
            filter_text: Optional text to filter logs (case-insensitive)
            
        Returns:
            List of dicts with timestamp, stream, message fields
        """
        start_time = int((datetime.now() - timedelta(minutes=minutes)).timestamp() * 1000)
        
        try:
            # Performance optimization: Get recent log streams first
            # This avoids fetching thousands of old logs when we only need recent ones
            streams_response = self.client.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=10  # Get the 10 most recent streams
            )
            
            recent_streams = [s['logStreamName'] for s in streams_response.get('logStreams', [])]
            
            # If we have recent streams, query them directly (much faster!)
            if recent_streams and not filter_text:
                events = []
                
                # Fetch logs from recent streams only
                for stream_name in recent_streams[:5]:  # Check top 5 streams
                    try:
                        response = self.client.filter_log_events(
                            logGroupName=log_group_name,
                            logStreamNames=[stream_name],
                            startTime=start_time,
                            limit=min(limit * 2, 1000)  # Fetch extra in case of filtering
                        )
                        events.extend(response.get('events', []))
                        
                        # Stop early if we have enough
                        if len(events) >= limit * 2:
                            break
                    except Exception:
                        continue
                
                # Sort by timestamp descending
                events.sort(key=lambda x: x['timestamp'], reverse=True)
                
            else:
                # Fallback: query all streams (slower, but needed for text filtering)
                events = []
                next_token = None
                max_iterations = 3 if minutes <= 60 else 10  # Fewer iterations for short time windows
                iteration = 0
                
                while iteration < max_iterations and len(events) < limit * 3:
                    kwargs = {
                        'logGroupName': log_group_name,
                        'startTime': start_time,
                        'limit': 1000
                    }
                    
                    if next_token:
                        kwargs['nextToken'] = next_token
                    
                    response = self.client.filter_log_events(**kwargs)
                    batch = response.get('events', [])
                    
                    # Apply text filter if provided
                    if filter_text:
                        batch = [e for e in batch if filter_text.lower() in e['message'].lower()]
                    
                    events.extend(batch)
                    
                    next_token = response.get('nextToken')
                    if not next_token:
                        break
                    
                    iteration += 1
                
                # Sort events by timestamp (newest first)
                events.sort(key=lambda x: x['timestamp'], reverse=True)
            
            # Format events for UI (take only the latest 'limit' events)
            formatted_logs = []
            for event in events[:limit]:
                formatted_logs.append({
                    'timestamp': datetime.fromtimestamp(event['timestamp'] / 1000),
                    'stream': event.get('logStreamName', 'unknown'),
                    'message': event['message']
                })
            
            return formatted_logs
            
        except self.client.exceptions.ResourceNotFoundException:
            return []
        except Exception as e:
            print(f"Failed to fetch logs: {e}")
            return []
    
    def describe_log_groups(self, log_group_names: Optional[List[str]] = None) -> dict:
        """
        Get detailed metadata for log groups.
        
        Args:
            log_group_names: Optional list of log group names to describe.
                           If None, describes all log groups.
        
        Returns:
            Dict mapping log group name to metadata dict
        """
        try:
            result = {}
            
            if log_group_names:
                # Get info for specific log groups
                for lg_name in log_group_names:
                    response = self.client.describe_log_groups(
                        logGroupNamePrefix=lg_name,
                        limit=1
                    )
                    
                    if response.get('logGroups'):
                        lg = response['logGroups'][0]
                        # Only include if exact match
                        if lg['logGroupName'] == lg_name:
                            result[lg_name] = self._format_log_group_metadata(lg)
            else:
                # Get all log groups (paginated)
                response = self.client.describe_log_groups(limit=50)
                for lg in response.get('logGroups', []):
                    result[lg['logGroupName']] = self._format_log_group_metadata(lg)
            
            return result
        except Exception as e:
            print(f"Failed to describe log groups: {e}")
            return {}
    
    def _format_log_group_metadata(self, log_group: dict) -> dict:
        """Format log group metadata for display."""
        stored_mb = log_group.get('storedBytes', 0) / (1024 * 1024)
        
        return {
            'name': log_group.get('logGroupName'),
            'stored_bytes': log_group.get('storedBytes', 0),
            'stored_mb': round(stored_mb, 2),
            'retention_days': log_group.get('retentionInDays', 'Never expire'),
            'created_time': datetime.fromtimestamp(
                log_group.get('creationTime', 0) / 1000
            ) if log_group.get('creationTime') else None,
            'metric_filter_count': log_group.get('metricFilterCount', 0)
        }
