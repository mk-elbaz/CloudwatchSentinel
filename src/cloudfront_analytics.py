"""
CloudFront Analytics Module
Fetches and analyzes CloudFront access logs for api.example.com
"""

import boto3
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import gzip
from io import BytesIO
from collections import defaultdict
import re
from urllib.parse import unquote


class CloudFrontAnalytics:
    """Analyzes CloudFront access logs"""
    
    def __init__(self):
        self.s3 = boto3.client('s3')
        self.bucket_name = os.getenv("CLOUDFRONT_LOG_BUCKET", "example-cloudfront-logs")
        self.log_prefix = "cloudfront/"
    
    def get_log_files(self, start_date: datetime, end_date: datetime) -> List[str]:
        """Get list of log files in date range"""
        try:
            response = self.s3.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=self.log_prefix
            )
            
            if 'Contents' not in response:
                return []
            
            log_files = []
            for obj in response['Contents']:
                key = obj['Key']
                last_modified = obj['LastModified'].replace(tzinfo=None)
                
                # Filter by date range
                if start_date <= last_modified <= end_date:
                    log_files.append(key)
            
            return log_files
            
        except Exception as e:
            print(f"Error fetching log files: {str(e)}")
            return []
    
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single CloudFront log line"""
        if line.startswith('#'):
            return None
        
        fields = line.split('\t')
        if len(fields) < 24:
            return None
        
        try:
            return {
                'date': fields[0],
                'time': fields[1],
                'edge_location': fields[2],
                'bytes': int(fields[3]) if fields[3] != '-' else 0,
                'ip': fields[4],
                'method': fields[5],
                'host': fields[6],
                'uri': unquote(fields[7]),
                'status': int(fields[8]) if fields[8] != '-' else 0,
                'referrer': unquote(fields[9]) if fields[9] != '-' else None,
                'user_agent': unquote(fields[10]) if fields[10] != '-' else None,
                'query_string': unquote(fields[11]) if fields[11] != '-' else None,
                'cookie': fields[12] if fields[12] != '-' else None,
                'result_type': fields[13],
                'request_id': fields[14],
                'host_header': fields[15],
                'protocol': fields[16],
                'bytes_sent': int(fields[17]) if fields[17] != '-' else 0,
                'time_taken': float(fields[18]) if fields[18] != '-' else 0,
            }
        except (IndexError, ValueError) as e:
            return None
    
    def download_and_parse_log(self, log_key: str) -> List[Dict]:
        """Download and parse a log file"""
        try:
            response = self.s3.get_object(Bucket=self.bucket_name, Key=log_key)
            
            # CloudFront logs are gzipped
            with gzip.GzipFile(fileobj=BytesIO(response['Body'].read())) as gzipfile:
                content = gzipfile.read().decode('utf-8')
            
            entries = []
            for line in content.split('\n'):
                parsed = self.parse_log_line(line)
                if parsed:
                    entries.append(parsed)
            
            return entries
            
        except Exception as e:
            print(f"Error parsing log {log_key}: {str(e)}")
            return []
    
    def analyze_logs(self, start_date: datetime, end_date: datetime) -> Dict:
        """Analyze logs and return statistics"""
        log_files = self.get_log_files(start_date, end_date)
        
        if not log_files:
            return self._empty_stats()
        
        # Aggregate data
        unique_ips = set()
        page_views = defaultdict(int)
        referrers = defaultdict(int)
        status_codes = defaultdict(int)
        user_agents = defaultdict(int)
        hourly_traffic = defaultdict(int)
        daily_traffic = defaultdict(int)
        total_bytes = 0
        total_requests = 0
        
        # Process each log file
        for log_file in log_files[:50]:  # Limit to 50 files for performance
            entries = self.download_and_parse_log(log_file)
            
            for entry in entries:
                total_requests += 1
                unique_ips.add(entry['ip'])
                
                # Page views (only HTML pages, exclude assets)
                uri = entry['uri']
                if not self._is_asset(uri):
                    page_views[uri] += 1
                
                # Referrers
                if entry['referrer'] and entry['referrer'] != '-':
                    referrers[entry['referrer']] += 1
                
                # Status codes
                status_codes[entry['status']] += 1
                
                # User agents (simplified)
                ua = self._simplify_user_agent(entry['user_agent'])
                user_agents[ua] += 1
                
                # Traffic by hour
                hour = f"{entry['date']} {entry['time'][:2]}:00"
                hourly_traffic[hour] += 1
                
                # Traffic by day
                daily_traffic[entry['date']] += 1
                
                # Bytes
                total_bytes += entry['bytes_sent']
        
        return {
            'total_requests': total_requests,
            'unique_visitors': len(unique_ips),
            'total_page_views': sum(page_views.values()),
            'total_bytes': total_bytes,
            'top_pages': sorted(page_views.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_referrers': sorted(referrers.items(), key=lambda x: x[1], reverse=True)[:10],
            'status_codes': dict(status_codes),
            'browsers': sorted(user_agents.items(), key=lambda x: x[1], reverse=True)[:10],
            'hourly_traffic': sorted(hourly_traffic.items()),
            'daily_traffic': sorted(daily_traffic.items()),
            'log_files_processed': len(log_files)
        }
    
    def _is_asset(self, uri: str) -> bool:
        """Check if URI is a static asset"""
        asset_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', 
                           '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map']
        return any(uri.lower().endswith(ext) for ext in asset_extensions)
    
    def _simplify_user_agent(self, user_agent: str) -> str:
        """Simplify user agent string to browser name"""
        if not user_agent:
            return 'Unknown'
        
        ua = user_agent.lower()
        if 'chrome' in ua and 'edg' not in ua:
            return 'Chrome'
        elif 'safari' in ua and 'chrome' not in ua:
            return 'Safari'
        elif 'firefox' in ua:
            return 'Firefox'
        elif 'edg' in ua:
            return 'Edge'
        elif 'bot' in ua or 'crawler' in ua or 'spider' in ua:
            return 'Bot'
        else:
            return 'Other'
    
    def _empty_stats(self) -> Dict:
        """Return empty stats structure"""
        return {
            'total_requests': 0,
            'unique_visitors': 0,
            'total_page_views': 0,
            'total_bytes': 0,
            'top_pages': [],
            'top_referrers': [],
            'status_codes': {},
            'browsers': [],
            'hourly_traffic': [],
            'daily_traffic': [],
            'log_files_processed': 0
        }
    
    def get_recent_stats(self, days: int = 7) -> Dict:
        """Get statistics for recent days"""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        return self.analyze_logs(start_date, end_date)
    
    def get_today_stats(self) -> Dict:
        """Get statistics for today"""
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        tomorrow = today + timedelta(days=1)
        
        return self.analyze_logs(today, tomorrow)
