"""
AWS Service Quota Monitor.
Tracks service quotas vs current usage and alerts before hitting limits.
"""

import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from openai import OpenAI
import os
import json
from botocore.exceptions import ClientError, NoCredentialsError


class AWSQuotaMonitor:
    """Monitors AWS service quotas and usage to prevent hitting limits."""
    
    # Common service quotas to monitor
    COMMON_QUOTAS = {
        'ec2': [
            ('L-1216C47A', 'Running On-Demand Standard instances'),
            ('L-34B43A08', 'All Standard Spot Instance Requests'),
            ('L-0E3CBAB9', 'EC2-VPC Elastic IPs'),
        ],
        'vpc': [
            ('L-F678F1CE', 'VPCs per Region'),
            ('L-A4707A72', 'Internet gateways per Region'),
            ('L-DF5E4CA3', 'NAT gateways per Availability Zone'),
        ],
        'lambda': [
            ('L-B99A9384', 'Concurrent executions'),
            ('L-2ACBD22F', 'Function and layer storage'),
        ],
        'rds': [
            ('L-7B6409FD', 'DB instances'),
            ('L-952B80B8', 'DB clusters'),
            ('L-DE55804A', 'Total storage for all DB instances'),
        ],
        's3': [
            ('L-DC2B2D3D', 'Buckets'),
        ],
        'iam': [
            ('L-F4A5425F', 'Users'),
            ('L-FE177D64', 'Roles'),
            ('L-BF35879D', 'Groups'),
        ],
        'elasticloadbalancing': [
            ('L-53DA6B97', 'Application Load Balancers per Region'),
            ('L-B6DF7632', 'Network Load Balancers per Region'),
        ],
        'sns': [
            ('L-61103206', 'Topics per Account'),
        ],
        'sqs': [
            ('L-848D3E6C', 'Queues per Account'),
        ],
        'dynamodb': [
            ('L-F98FE922', 'Tables per Region'),
        ],
    }
    
    def __init__(self):
        """Initialize boto3 clients and OpenAI client."""
        self.region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        
        # Initialize OpenAI for AI analysis
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key:
            self.openai_client = OpenAI(api_key=api_key)
            self.model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
        else:
            self.openai_client = None
        
        # Track service availability
        self.service_status = {}
    
    def _get_client(self, service: str):
        """Get a boto3 client for a specific service with graceful fallback."""
        try:
            return boto3.client(service, region_name=self.region)
        except Exception as e:
            self.service_status[service] = f"Failed to initialize: {str(e)}"
            return None
    
    def _safe_api_call(self, service_name: str, func, *args, **kwargs) -> Optional[Any]:
        """Execute an API call with graceful error handling."""
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code in ['AccessDenied', 'UnauthorizedAccess', 'AccessDeniedException']:
                self.service_status[service_name] = f"Access denied - check IAM permissions"
            elif error_code == 'OptInRequired':
                self.service_status[service_name] = f"Service not enabled in this account"
            elif error_code == 'NoSuchResourceException':
                self.service_status[service_name] = f"Resource not found"
            else:
                self.service_status[service_name] = f"Error: {error_code}"
            return None
        except NoCredentialsError:
            self.service_status[service_name] = "No AWS credentials configured"
            return None
        except Exception as e:
            self.service_status[service_name] = f"Error: {str(e)}"
            return None
    
    def get_quota_with_usage(self, service_code: str, quota_code: str) -> Optional[Dict[str, Any]]:
        """Get a specific quota along with current usage."""
        sq = self._get_client('service-quotas')
        if not sq:
            return None
        
        quota_info = {}
        
        # Get quota value
        try:
            quota_response = sq.get_service_quota(
                ServiceCode=service_code,
                QuotaCode=quota_code
            )
            quota = quota_response.get('Quota', {})
            quota_info = {
                'service_code': service_code,
                'quota_code': quota_code,
                'quota_name': quota.get('QuotaName', 'Unknown'),
                'quota_value': quota.get('Value', 0),
                'unit': quota.get('Unit', 'None'),
                'adjustable': quota.get('Adjustable', False),
                'global_quota': quota.get('GlobalQuota', False)
            }
        except ClientError as e:
            # Try getting default quota if service quota not found
            try:
                default_response = sq.get_aws_default_service_quota(
                    ServiceCode=service_code,
                    QuotaCode=quota_code
                )
                quota = default_response.get('Quota', {})
                quota_info = {
                    'service_code': service_code,
                    'quota_code': quota_code,
                    'quota_name': quota.get('QuotaName', 'Unknown'),
                    'quota_value': quota.get('Value', 0),
                    'unit': quota.get('Unit', 'None'),
                    'adjustable': quota.get('Adjustable', False),
                    'global_quota': quota.get('GlobalQuota', False),
                    'is_default': True
                }
            except ClientError:
                return None
        
        # Get current usage if available
        try:
            # Check CloudWatch for usage metrics
            cw = self._get_client('cloudwatch')
            if cw and quota_info.get('quota_name'):
                # Try to get usage metric
                usage_response = sq.get_service_quota(
                    ServiceCode=service_code,
                    QuotaCode=quota_code
                )
                usage_metric = usage_response.get('Quota', {}).get('UsageMetric')
                
                if usage_metric:
                    end_time = datetime.utcnow()
                    start_time = end_time - timedelta(hours=1)
                    
                    metric_response = cw.get_metric_statistics(
                        Namespace=usage_metric.get('MetricNamespace', 'AWS/Usage'),
                        MetricName=usage_metric.get('MetricName', ''),
                        Dimensions=[
                            {'Name': k, 'Value': v}
                            for k, v in usage_metric.get('MetricDimensions', {}).items()
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=['Maximum']
                    )
                    
                    if metric_response.get('Datapoints'):
                        latest = max(metric_response['Datapoints'], key=lambda x: x['Timestamp'])
                        quota_info['current_usage'] = latest.get('Maximum', 0)
                        quota_info['usage_percentage'] = round(
                            (quota_info['current_usage'] / quota_info['quota_value']) * 100, 1
                        ) if quota_info['quota_value'] > 0 else 0
        except ClientError:
            pass
        
        return quota_info
    
    def get_ec2_usage(self) -> Dict[str, Any]:
        """Get EC2-specific usage counts."""
        ec2 = self._get_client('ec2')
        if not ec2:
            return {}
        
        usage = {}
        
        try:
            # Running instances
            instances = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            instance_count = sum(
                len(r['Instances']) for r in instances.get('Reservations', [])
            )
            usage['running_instances'] = instance_count
            
            # Elastic IPs
            addresses = ec2.describe_addresses()
            usage['elastic_ips'] = len(addresses.get('Addresses', []))
            
            # VPCs
            vpcs = ec2.describe_vpcs()
            usage['vpcs'] = len(vpcs.get('Vpcs', []))
            
            # Security Groups
            security_groups = ec2.describe_security_groups()
            usage['security_groups'] = len(security_groups.get('SecurityGroups', []))
            
            # EBS Volumes
            volumes = ec2.describe_volumes()
            usage['ebs_volumes'] = len(volumes.get('Volumes', []))
            total_storage = sum(v.get('Size', 0) for v in volumes.get('Volumes', []))
            usage['ebs_total_storage_gb'] = total_storage
            
            # Snapshots
            snapshots = ec2.describe_snapshots(OwnerIds=['self'])
            usage['snapshots'] = len(snapshots.get('Snapshots', []))
            
            # Internet Gateways
            igws = ec2.describe_internet_gateways()
            usage['internet_gateways'] = len(igws.get('InternetGateways', []))
            
            # NAT Gateways
            nat_gws = ec2.describe_nat_gateways(
                Filters=[{'Name': 'state', 'Values': ['available']}]
            )
            usage['nat_gateways'] = len(nat_gws.get('NatGateways', []))
            
        except ClientError as e:
            self.service_status['ec2_usage'] = f"Error: {e}"
        
        return usage
    
    def get_lambda_usage(self) -> Dict[str, Any]:
        """Get Lambda-specific usage counts."""
        lambda_client = self._get_client('lambda')
        if not lambda_client:
            return {}
        
        usage = {}
        
        try:
            # Function count
            functions = lambda_client.list_functions()
            usage['functions'] = len(functions.get('Functions', []))
            
            # Total code storage
            account_settings = lambda_client.get_account_settings()
            usage['total_code_size_mb'] = round(
                account_settings.get('AccountUsage', {}).get('TotalCodeSize', 0) / (1024 * 1024), 2
            )
            usage['function_count'] = account_settings.get('AccountUsage', {}).get('FunctionCount', 0)
            
            # Concurrent executions limit
            usage['concurrent_execution_limit'] = account_settings.get('AccountLimit', {}).get(
                'ConcurrentExecutions', 1000
            )
            usage['unreserved_concurrent_executions'] = account_settings.get('AccountLimit', {}).get(
                'UnreservedConcurrentExecutions', 0
            )
            
        except ClientError as e:
            self.service_status['lambda_usage'] = f"Error: {e}"
        
        return usage
    
    def get_rds_usage(self) -> Dict[str, Any]:
        """Get RDS-specific usage counts."""
        rds = self._get_client('rds')
        if not rds:
            return {}
        
        usage = {}
        
        try:
            # DB instances
            instances = rds.describe_db_instances()
            usage['db_instances'] = len(instances.get('DBInstances', []))
            
            # Total storage
            total_storage = sum(
                db.get('AllocatedStorage', 0) for db in instances.get('DBInstances', [])
            )
            usage['total_storage_gb'] = total_storage
            
            # DB clusters (Aurora)
            clusters = rds.describe_db_clusters()
            usage['db_clusters'] = len(clusters.get('DBClusters', []))
            
            # Snapshots
            snapshots = rds.describe_db_snapshots(SnapshotType='manual')
            usage['manual_snapshots'] = len(snapshots.get('DBSnapshots', []))
            
            # Parameter groups
            param_groups = rds.describe_db_parameter_groups()
            usage['parameter_groups'] = len(param_groups.get('DBParameterGroups', []))
            
        except ClientError as e:
            self.service_status['rds_usage'] = f"Error: {e}"
        
        return usage
    
    def get_s3_usage(self) -> Dict[str, Any]:
        """Get S3-specific usage counts."""
        s3 = self._get_client('s3')
        if not s3:
            return {}
        
        usage = {}
        
        try:
            buckets = s3.list_buckets()
            usage['buckets'] = len(buckets.get('Buckets', []))
        except ClientError as e:
            self.service_status['s3_usage'] = f"Error: {e}"
        
        return usage
    
    def get_iam_usage(self) -> Dict[str, Any]:
        """Get IAM-specific usage counts."""
        iam = self._get_client('iam')
        if not iam:
            return {}
        
        usage = {}
        
        try:
            # Get account summary
            summary = iam.get_account_summary()
            summary_map = summary.get('SummaryMap', {})
            
            usage['users'] = summary_map.get('Users', 0)
            usage['users_quota'] = summary_map.get('UsersQuota', 5000)
            usage['groups'] = summary_map.get('Groups', 0)
            usage['groups_quota'] = summary_map.get('GroupsQuota', 300)
            usage['roles'] = summary_map.get('Roles', 0)
            usage['roles_quota'] = summary_map.get('RolesQuota', 1000)
            usage['policies'] = summary_map.get('Policies', 0)
            usage['policies_quota'] = summary_map.get('PoliciesQuota', 1500)
            usage['server_certificates'] = summary_map.get('ServerCertificates', 0)
            usage['server_certificates_quota'] = summary_map.get('ServerCertificatesQuota', 20)
            usage['mfa_devices'] = summary_map.get('MFADevices', 0)
            usage['access_keys_per_user'] = summary_map.get('AccessKeysPerUserQuota', 2)
            
        except ClientError as e:
            self.service_status['iam_usage'] = f"Error: {e}"
        
        return usage
    
    def get_elb_usage(self) -> Dict[str, Any]:
        """Get ELB-specific usage counts."""
        elbv2 = self._get_client('elbv2')
        if not elbv2:
            return {}
        
        usage = {}
        
        try:
            load_balancers = elbv2.describe_load_balancers()
            
            alb_count = 0
            nlb_count = 0
            
            for lb in load_balancers.get('LoadBalancers', []):
                lb_type = lb.get('Type', 'application')
                if lb_type == 'application':
                    alb_count += 1
                elif lb_type == 'network':
                    nlb_count += 1
            
            usage['application_load_balancers'] = alb_count
            usage['network_load_balancers'] = nlb_count
            
            # Target groups
            target_groups = elbv2.describe_target_groups()
            usage['target_groups'] = len(target_groups.get('TargetGroups', []))
            
        except ClientError as e:
            self.service_status['elb_usage'] = f"Error: {e}"
        
        return usage
    
    def check_all_quotas(self) -> Dict[str, Any]:
        """Check all common quotas and compare with usage."""
        sq = self._get_client('service-quotas')
        if not sq:
            return {'quotas': [], 'error': 'Service Quotas client unavailable'}
        
        quotas = []
        alerts = []
        
        # Get actual usage first
        ec2_usage = self.get_ec2_usage()
        lambda_usage = self.get_lambda_usage()
        rds_usage = self.get_rds_usage()
        s3_usage = self.get_s3_usage()
        iam_usage = self.get_iam_usage()
        elb_usage = self.get_elb_usage()
        
        # Check EC2 quotas
        quota_info = self.get_quota_with_usage('ec2', 'L-0E3CBAB9')  # Elastic IPs
        if quota_info:
            quota_info['current_usage'] = ec2_usage.get('elastic_ips', 0)
            quota_info['usage_percentage'] = round(
                (quota_info['current_usage'] / max(quota_info['quota_value'], 1)) * 100, 1
            )
            quotas.append(quota_info)
            if quota_info['usage_percentage'] >= 80:
                alerts.append({
                    'service': 'EC2',
                    'quota': 'Elastic IPs',
                    'usage_percentage': quota_info['usage_percentage'],
                    'severity': 'CRITICAL' if quota_info['usage_percentage'] >= 90 else 'WARNING'
                })
        
        # VPC quota
        quota_info = self.get_quota_with_usage('vpc', 'L-F678F1CE')  # VPCs
        if quota_info:
            quota_info['current_usage'] = ec2_usage.get('vpcs', 0)
            quota_info['usage_percentage'] = round(
                (quota_info['current_usage'] / max(quota_info['quota_value'], 1)) * 100, 1
            )
            quotas.append(quota_info)
            if quota_info['usage_percentage'] >= 80:
                alerts.append({
                    'service': 'VPC',
                    'quota': 'VPCs per Region',
                    'usage_percentage': quota_info['usage_percentage'],
                    'severity': 'CRITICAL' if quota_info['usage_percentage'] >= 90 else 'WARNING'
                })
        
        # Lambda quotas
        quota_info = self.get_quota_with_usage('lambda', 'L-B99A9384')  # Concurrent executions
        if quota_info:
            quota_info['current_usage'] = lambda_usage.get('concurrent_execution_limit', 0) - lambda_usage.get('unreserved_concurrent_executions', 0)
            quotas.append(quota_info)
        
        # S3 buckets
        quota_info = self.get_quota_with_usage('s3', 'L-DC2B2D3D')  # Buckets
        if quota_info:
            quota_info['current_usage'] = s3_usage.get('buckets', 0)
            quota_info['usage_percentage'] = round(
                (quota_info['current_usage'] / max(quota_info['quota_value'], 1)) * 100, 1
            )
            quotas.append(quota_info)
        
        # RDS instances
        quota_info = self.get_quota_with_usage('rds', 'L-7B6409FD')  # DB instances
        if quota_info:
            quota_info['current_usage'] = rds_usage.get('db_instances', 0)
            quota_info['usage_percentage'] = round(
                (quota_info['current_usage'] / max(quota_info['quota_value'], 1)) * 100, 1
            )
            quotas.append(quota_info)
            if quota_info['usage_percentage'] >= 80:
                alerts.append({
                    'service': 'RDS',
                    'quota': 'DB Instances',
                    'usage_percentage': quota_info['usage_percentage'],
                    'severity': 'CRITICAL' if quota_info['usage_percentage'] >= 90 else 'WARNING'
                })
        
        # ELB quotas
        quota_info = self.get_quota_with_usage('elasticloadbalancing', 'L-53DA6B97')  # ALBs
        if quota_info:
            quota_info['current_usage'] = elb_usage.get('application_load_balancers', 0)
            quota_info['usage_percentage'] = round(
                (quota_info['current_usage'] / max(quota_info['quota_value'], 1)) * 100, 1
            )
            quotas.append(quota_info)
        
        # IAM quotas from account summary
        if iam_usage:
            iam_quotas = [
                ('users', 'users_quota', 'IAM Users'),
                ('roles', 'roles_quota', 'IAM Roles'),
                ('groups', 'groups_quota', 'IAM Groups'),
                ('policies', 'policies_quota', 'IAM Policies'),
            ]
            for usage_key, quota_key, name in iam_quotas:
                current = iam_usage.get(usage_key, 0)
                limit = iam_usage.get(quota_key, 0)
                if limit > 0:
                    pct = round((current / limit) * 100, 1)
                    quotas.append({
                        'service_code': 'iam',
                        'quota_name': name,
                        'quota_value': limit,
                        'current_usage': current,
                        'usage_percentage': pct,
                        'adjustable': True
                    })
                    if pct >= 80:
                        alerts.append({
                            'service': 'IAM',
                            'quota': name,
                            'usage_percentage': pct,
                            'severity': 'CRITICAL' if pct >= 90 else 'WARNING'
                        })
        
        return {
            'quotas': quotas,
            'alerts': alerts,
            'usage_summary': {
                'ec2': ec2_usage,
                'lambda': lambda_usage,
                'rds': rds_usage,
                's3': s3_usage,
                'iam': iam_usage,
                'elb': elb_usage
            }
        }
    
    def get_quota_increase_history(self) -> List[Dict[str, Any]]:
        """Get history of quota increase requests."""
        sq = self._get_client('service-quotas')
        if not sq:
            return []
        
        requests = []
        
        try:
            paginator = sq.get_paginator('list_requested_service_quota_change_history')
            for page in paginator.paginate():
                for req in page.get('RequestedQuotas', []):
                    requests.append({
                        'id': req.get('Id'),
                        'service_code': req.get('ServiceCode'),
                        'quota_name': req.get('QuotaName'),
                        'status': req.get('Status'),
                        'desired_value': req.get('DesiredValue'),
                        'created': req.get('Created', '').isoformat() if req.get('Created') else None,
                        'case_id': req.get('CaseId')
                    })
        except ClientError:
            pass
        
        return requests
    
    def run_full_quota_check(self) -> Dict[str, Any]:
        """Run comprehensive quota monitoring."""
        self.service_status = {}  # Reset status
        
        quota_results = self.check_all_quotas()
        request_history = self.get_quota_increase_history()
        
        # Calculate summary
        quotas_checked = len(quota_results.get('quotas', []))
        critical_alerts = len([a for a in quota_results.get('alerts', []) if a['severity'] == 'CRITICAL'])
        warning_alerts = len([a for a in quota_results.get('alerts', []) if a['severity'] == 'WARNING'])
        
        results = {
            'check_time': datetime.now().isoformat(),
            'quotas': quota_results.get('quotas', []),
            'alerts': quota_results.get('alerts', []),
            'usage_summary': quota_results.get('usage_summary', {}),
            'quota_increase_requests': request_history,
            'summary': {
                'quotas_checked': quotas_checked,
                'critical_alerts': critical_alerts,
                'warning_alerts': warning_alerts,
                'total_alerts': critical_alerts + warning_alerts
            },
            'service_status': self.service_status
        }
        
        return results
    
    def get_ai_recommendations(self, quota_results: Dict[str, Any]) -> Optional[str]:
        """Get AI-powered quota management recommendations."""
        if not self.openai_client:
            return None
        
        # Prepare summary for AI
        summary = {
            'alerts': quota_results.get('alerts', []),
            'high_usage_quotas': [
                q for q in quota_results.get('quotas', [])
                if q.get('usage_percentage', 0) >= 60
            ],
            'usage_summary': quota_results.get('usage_summary', {})
        }
        
        system_prompt = """You are an AWS capacity planning expert. Analyze the service quota usage and provide:

1. **Immediate Actions**: Quotas that need immediate attention
2. **Quota Increase Recommendations**: Which limits to request increases for
3. **Capacity Planning**: Forecast based on current growth
4. **Optimization Suggestions**: How to reduce usage where possible
5. **Best Practices**: AWS recommendations for quota management

Include specific AWS CLI commands or console steps for requesting quota increases.
Format your response in clear Markdown with headers and bullet points."""

        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze this AWS quota data:\n\n{json.dumps(summary, indent=2, default=str)}"}
                ],
                max_tokens=1500,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating AI recommendations: {str(e)}"
    
    def request_quota_increase(self, service_code: str, quota_code: str, desired_value: float) -> Dict[str, Any]:
        """Request a quota increase (returns info about how to do it)."""
        sq = self._get_client('service-quotas')
        if not sq:
            return {'error': 'Service Quotas client unavailable'}
        
        try:
            # Check if quota is adjustable
            quota = sq.get_service_quota(
                ServiceCode=service_code,
                QuotaCode=quota_code
            )
            
            if not quota.get('Quota', {}).get('Adjustable', False):
                return {
                    'error': 'This quota is not adjustable',
                    'quota_name': quota.get('Quota', {}).get('QuotaName'),
                    'current_value': quota.get('Quota', {}).get('Value')
                }
            
            # Request the increase
            response = sq.request_service_quota_increase(
                ServiceCode=service_code,
                QuotaCode=quota_code,
                DesiredValue=desired_value
            )
            
            return {
                'success': True,
                'request_id': response.get('RequestedQuota', {}).get('Id'),
                'status': response.get('RequestedQuota', {}).get('Status'),
                'case_id': response.get('RequestedQuota', {}).get('CaseId')
            }
        except ClientError as e:
            return {'error': str(e)}
