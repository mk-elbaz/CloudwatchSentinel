"""
AWS Cost Analyzer with AI-powered insights.
Uses AWS Cost Explorer API to fetch billing data and OpenAI to analyze spending patterns.
Includes architecture discovery for context-aware recommendations.
"""

import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from openai import OpenAI
import os
import json


class AWSCostAnalyzer:
    """Analyzes AWS costs using Cost Explorer API and provides AI-powered insights."""
    
    def __init__(self):
        """Initialize boto3 Cost Explorer client and OpenAI client."""
        self.region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        self.ce_client = boto3.client('ce', region_name=self.region)
        
        # Initialize OpenAI for AI analysis
        api_key = os.getenv('OPENAI_API_KEY')
        if api_key:
            self.openai_client = OpenAI(api_key=api_key)
            self.model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
        else:
            self.openai_client = None
    
    def _get_client(self, service: str):
        """Get a boto3 client for a specific service."""
        return boto3.client(service, region_name=self.region)
    
    def test_connection(self) -> bool:
        """Test if AWS Cost Explorer is accessible."""
        try:
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
            self.ce_client.get_cost_and_usage(
                TimePeriod={'Start': start_date, 'End': end_date},
                Granularity='DAILY',
                Metrics=['UnblendedCost']
            )
            return True
        except Exception as e:
            print(f"Cost Explorer Connection Failed: {e}")
            return False
    
    def get_cost_summary(self, days: int = 30, year: int = None, month: int = None) -> Dict[str, Any]:
        """
        Get cost summary for the specified period.
        
        Args:
            days: Number of days to look back (used if year/month not specified)
            year: Specific year (e.g., 2025)
            month: Specific month (1-12)
            
        Returns:
            Dictionary with total cost, daily breakdown, and service breakdown
        """
        # If year and month specified, use that month's range
        if year and month:
            start_date = f"{year}-{month:02d}-01"
            # Calculate end of month
            if month == 12:
                end_date = f"{year + 1}-01-01"
            else:
                end_date = f"{year}-{month + 1:02d}-01"
            period_label = f"{year}-{month:02d}"
        else:
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            period_label = f"Last {days} days"
        
        try:
            # Get total cost and daily breakdown
            daily_response = self.ce_client.get_cost_and_usage(
                TimePeriod={'Start': start_date, 'End': end_date},
                Granularity='DAILY',
                Metrics=['UnblendedCost', 'UsageQuantity']
            )
            
            # Get cost by service
            service_response = self.ce_client.get_cost_and_usage(
                TimePeriod={'Start': start_date, 'End': end_date},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            )
            
            # Process daily costs
            daily_costs = []
            total_cost = 0.0
            for result in daily_response['ResultsByTime']:
                date = result['TimePeriod']['Start']
                amount = float(result['Total']['UnblendedCost']['Amount'])
                daily_costs.append({
                    'date': date,
                    'cost': round(amount, 2),
                    'currency': result['Total']['UnblendedCost']['Unit']
                })
                total_cost += amount
            
            # Process service costs
            service_costs = []
            for result in service_response['ResultsByTime']:
                for group in result.get('Groups', []):
                    service_name = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    if amount > 0.01:  # Filter out negligible costs
                        service_costs.append({
                            'service': service_name,
                            'cost': round(amount, 2),
                            'currency': group['Metrics']['UnblendedCost']['Unit']
                        })
            
            # Sort services by cost descending
            service_costs.sort(key=lambda x: x['cost'], reverse=True)
            
            return {
                'total_cost': round(total_cost, 2),
                'currency': 'USD',
                'period_days': len(daily_costs),
                'period_label': period_label,
                'year': year,
                'month': month,
                'start_date': start_date,
                'end_date': end_date,
                'daily_costs': daily_costs,
                'service_breakdown': service_costs,
                'avg_daily_cost': round(total_cost / max(len(daily_costs), 1), 2)
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'total_cost': 0,
                'daily_costs': [],
                'service_breakdown': []
            }
    
    def get_cost_forecast(self, days: int = 30) -> Dict[str, Any]:
        """
        Get cost forecast for the next specified days.
        
        Args:
            days: Number of days to forecast (default 30)
            
        Returns:
            Dictionary with forecasted costs
        """
        start_date = datetime.now().strftime('%Y-%m-%d')
        end_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
        
        try:
            response = self.ce_client.get_cost_forecast(
                TimePeriod={'Start': start_date, 'End': end_date},
                Metric='UNBLENDED_COST',
                Granularity='MONTHLY'
            )
            
            return {
                'forecasted_total': round(float(response['Total']['Amount']), 2),
                'currency': response['Total']['Unit'],
                'forecast_period': f"{start_date} to {end_date}",
                'confidence_level': 'MEDIUM'  # AWS default
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'forecasted_total': 0
            }
    
    def get_cost_by_tag(self, tag_key: str, days: int = 30) -> Dict[str, Any]:
        """
        Get costs grouped by a specific tag (e.g., Environment, Project).
        
        Args:
            tag_key: The tag key to group by
            days: Number of days to look back
            
        Returns:
            Dictionary with costs grouped by tag value
        """
        end_date = datetime.now().strftime('%Y-%m-%d')
        start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        
        try:
            response = self.ce_client.get_cost_and_usage(
                TimePeriod={'Start': start_date, 'End': end_date},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[{'Type': 'TAG', 'Key': tag_key}]
            )
            
            tag_costs = []
            for result in response['ResultsByTime']:
                for group in result.get('Groups', []):
                    tag_value = group['Keys'][0].replace(f'{tag_key}$', '') or 'Untagged'
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    if amount > 0.01:
                        tag_costs.append({
                            'tag_value': tag_value,
                            'cost': round(amount, 2)
                        })
            
            tag_costs.sort(key=lambda x: x['cost'], reverse=True)
            
            return {
                'tag_key': tag_key,
                'costs': tag_costs,
                'period_days': days
            }
            
        except Exception as e:
            return {'error': str(e), 'costs': []}
    
    def get_cost_anomalies(self, days: int = 90) -> List[Dict[str, Any]]:
        """
        Detect cost anomalies using AWS Cost Anomaly Detection.
        
        Args:
            days: Number of days to look back for anomalies
            
        Returns:
            List of detected anomalies
        """
        try:
            # First, get anomaly monitors
            monitors_response = self.ce_client.get_anomaly_monitors(MaxResults=100)
            
            anomalies = []
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            # Get anomalies from all monitors
            for monitor in monitors_response.get('AnomalyMonitors', []):
                monitor_arn = monitor['MonitorArn']
                
                try:
                    anomaly_response = self.ce_client.get_anomalies(
                        MonitorArn=monitor_arn,
                        DateInterval={'StartDate': start_date, 'EndDate': end_date}
                    )
                    
                    for anomaly in anomaly_response.get('Anomalies', []):
                        anomalies.append({
                            'anomaly_id': anomaly.get('AnomalyId'),
                            'start_date': anomaly.get('AnomalyStartDate'),
                            'end_date': anomaly.get('AnomalyEndDate'),
                            'impact': anomaly.get('Impact', {}),
                            'root_causes': anomaly.get('RootCauses', []),
                            'feedback': anomaly.get('Feedback', 'NO_FEEDBACK')
                        })
                except Exception:
                    continue
            
            return anomalies
            
        except Exception as e:
            return [{'error': str(e)}]
    
    def get_top_cost_changes(self, days: int = 30) -> Dict[str, Any]:
        """
        Get services with the biggest cost changes compared to previous period.
        
        Args:
            days: Number of days for current period
            
        Returns:
            Dictionary with cost changes by service
        """
        # Current period
        current_end = datetime.now().strftime('%Y-%m-%d')
        current_start = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        
        # Previous period
        previous_end = current_start
        previous_start = (datetime.now() - timedelta(days=days*2)).strftime('%Y-%m-%d')
        
        return self._compare_periods(current_start, current_end, previous_start, previous_end)
    
    def get_month_over_month_changes(self, year: int, month: int) -> Dict[str, Any]:
        """
        Get cost changes comparing specified month to the previous month.
        
        Args:
            year: Year of the month to analyze
            month: Month to analyze (1-12)
            
        Returns:
            Dictionary with cost changes by service
        """
        # Current month period
        current_start = f"{year}-{month:02d}-01"
        if month == 12:
            current_end = f"{year + 1}-01-01"
        else:
            current_end = f"{year}-{month + 1:02d}-01"
        
        # Previous month period
        if month == 1:
            prev_year = year - 1
            prev_month = 12
        else:
            prev_year = year
            prev_month = month - 1
        
        previous_start = f"{prev_year}-{prev_month:02d}-01"
        previous_end = current_start
        
        result = self._compare_periods(current_start, current_end, previous_start, previous_end)
        result['current_month'] = f"{year}-{month:02d}"
        result['previous_month'] = f"{prev_year}-{prev_month:02d}"
        
        return result
    
    def _compare_periods(self, current_start: str, current_end: str, 
                         previous_start: str, previous_end: str) -> Dict[str, Any]:
        """
        Compare costs between two periods.
        
        Args:
            current_start: Start date of current period
            current_end: End date of current period
            previous_start: Start date of previous period
            previous_end: End date of previous period
            
        Returns:
            Dictionary with cost changes by service
        """
        try:
            # Get current period costs
            current_response = self.ce_client.get_cost_and_usage(
                TimePeriod={'Start': current_start, 'End': current_end},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            )
            
            # Get previous period costs
            previous_response = self.ce_client.get_cost_and_usage(
                TimePeriod={'Start': previous_start, 'End': previous_end},
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
            )
            
            # Process costs
            current_costs = {}
            current_total = 0.0
            for result in current_response['ResultsByTime']:
                for group in result.get('Groups', []):
                    service = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    current_costs[service] = amount
                    current_total += amount
            
            previous_costs = {}
            previous_total = 0.0
            for result in previous_response['ResultsByTime']:
                for group in result.get('Groups', []):
                    service = group['Keys'][0]
                    amount = float(group['Metrics']['UnblendedCost']['Amount'])
                    previous_costs[service] = amount
                    previous_total += amount
            
            # Calculate changes
            all_services = set(current_costs.keys()) | set(previous_costs.keys())
            changes = []
            
            for service in all_services:
                current = current_costs.get(service, 0)
                previous = previous_costs.get(service, 0)
                
                if previous > 0:
                    change_pct = ((current - previous) / previous) * 100
                elif current > 0:
                    change_pct = 100  # New service
                else:
                    change_pct = 0
                
                if abs(current - previous) > 0.1:  # Only significant changes
                    changes.append({
                        'service': service,
                        'current_cost': round(current, 2),
                        'previous_cost': round(previous, 2),
                        'change_amount': round(current - previous, 2),
                        'change_percent': round(change_pct, 1)
                    })
            
            # Sort by absolute change
            changes.sort(key=lambda x: abs(x['change_amount']), reverse=True)
            
            # Calculate total change
            total_change = current_total - previous_total
            total_change_pct = ((current_total - previous_total) / previous_total * 100) if previous_total > 0 else 0
            
            return {
                'current_period': f"{current_start} to {current_end}",
                'previous_period': f"{previous_start} to {previous_end}",
                'current_total': round(current_total, 2),
                'previous_total': round(previous_total, 2),
                'total_change': round(total_change, 2),
                'total_change_percent': round(total_change_pct, 1),
                'changes': changes[:15]  # Top 15 changes
            }
            
        except Exception as e:
            return {'error': str(e), 'changes': []}
    
    def get_multi_month_summary(self, num_months: int = 6) -> List[Dict[str, Any]]:
        """
        Get cost summary for multiple months.
        
        Args:
            num_months: Number of months to retrieve (default 6)
            
        Returns:
            List of monthly cost summaries
        """
        months = []
        today = datetime.now()
        
        for i in range(num_months):
            # Calculate month offset
            month = today.month - i
            year = today.year
            while month <= 0:
                month += 12
                year -= 1
            
            # Get start and end dates for this month
            start_date = f"{year}-{month:02d}-01"
            if month == 12:
                end_date = f"{year + 1}-01-01"
            else:
                end_date = f"{year}-{month + 1:02d}-01"
            
            # For current month, end at today
            if i == 0:
                end_date = (today + timedelta(days=1)).strftime('%Y-%m-%d')
            
            try:
                response = self.ce_client.get_cost_and_usage(
                    TimePeriod={'Start': start_date, 'End': end_date},
                    Granularity='MONTHLY',
                    Metrics=['UnblendedCost']
                )
                
                total = 0.0
                for result in response['ResultsByTime']:
                    total += float(result['Total']['UnblendedCost']['Amount'])
                
                month_name = datetime(year, month, 1).strftime('%B %Y')
                months.append({
                    'year': year,
                    'month': month,
                    'month_name': month_name,
                    'total_cost': round(total, 2),
                    'start_date': start_date,
                    'end_date': end_date
                })
            except Exception as e:
                months.append({
                    'year': year,
                    'month': month,
                    'month_name': datetime(year, month, 1).strftime('%B %Y'),
                    'total_cost': 0,
                    'error': str(e)
                })
        
        return months

    def get_rightsizing_recommendations(self) -> List[Dict[str, Any]]:
        """
        Get EC2 rightsizing recommendations from AWS.
        
        Returns:
            List of rightsizing recommendations
        """
        try:
            response = self.ce_client.get_rightsizing_recommendation(
                Service='AmazonEC2',
                Configuration={
                    'RecommendationTarget': 'SAME_INSTANCE_FAMILY',
                    'BenefitsConsidered': True
                }
            )
            
            recommendations = []
            for rec in response.get('RightsizingRecommendations', []):
                current_instance = rec.get('CurrentInstance', {})
                modify_rec = rec.get('ModifyRecommendationDetail', {})
                target_instances = modify_rec.get('TargetInstances', [{}])
                
                if target_instances:
                    target = target_instances[0]
                    recommendations.append({
                        'instance_id': current_instance.get('ResourceId'),
                        'current_type': current_instance.get('InstanceType'),
                        'recommended_type': target.get('InstanceType'),
                        'estimated_monthly_savings': target.get('EstimatedMonthlySavings', {}).get('Value', 0),
                        'savings_currency': target.get('EstimatedMonthlySavings', {}).get('Currency', 'USD')
                    })
            
            return recommendations
            
        except Exception as e:
            return [{'error': str(e)}]
    
    def get_savings_plans_recommendations(self) -> Dict[str, Any]:
        """
        Get Savings Plans recommendations.
        
        Returns:
            Dictionary with savings plan recommendations
        """
        try:
            response = self.ce_client.get_savings_plans_purchase_recommendation(
                SavingsPlansType='COMPUTE_SP',
                TermInYears='ONE_YEAR',
                PaymentOption='NO_UPFRONT',
                LookbackPeriodInDays='THIRTY_DAYS'
            )
            
            recommendations = []
            for rec in response.get('SavingsPlansPurchaseRecommendation', {}).get('SavingsPlansPurchaseRecommendationDetails', []):
                recommendations.append({
                    'hourly_commitment': rec.get('HourlyCommitmentToPurchase'),
                    'estimated_monthly_savings': rec.get('EstimatedMonthlySavingsAmount'),
                    'estimated_savings_percentage': rec.get('EstimatedSavingsPercentage'),
                    'current_on_demand_spend': rec.get('CurrentOnDemandSpend')
                })
            
            return {
                'recommendations': recommendations,
                'account_scope': response.get('SavingsPlansPurchaseRecommendation', {}).get('AccountScope', 'PAYER')
            }
            
        except Exception as e:
            return {'error': str(e), 'recommendations': []}
    
    def discover_architecture(self) -> Dict[str, Any]:
        """
        Discover AWS architecture and resources for context-aware analysis.
        
        Returns:
            Dictionary with discovered resources and configurations
        """
        architecture = {
            'region': self.region,
            'ec2_instances': [],
            'rds_databases': [],
            'lambda_functions': [],
            's3_buckets': [],
            'cloudfront_distributions': [],
            'elasticache_clusters': [],
            'api_gateways': [],
            'load_balancers': [],
            'ecs_services': [],
            'eks_clusters': [],
            'dynamodb_tables': [],
            'sqs_queues': [],
            'sns_topics': [],
        }
        
        # EC2 Instances
        try:
            ec2 = self._get_client('ec2')
            instances = ec2.describe_instances()
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    if instance['State']['Name'] != 'terminated':
                        name = next((t['Value'] for t in instance.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
                        architecture['ec2_instances'].append({
                            'id': instance['InstanceId'],
                            'name': name,
                            'type': instance['InstanceType'],
                            'state': instance['State']['Name'],
                            'az': instance.get('Placement', {}).get('AvailabilityZone'),
                            'platform': instance.get('Platform', 'Linux'),
                            'public_ip': instance.get('PublicIpAddress'),
                            'private_ip': instance.get('PrivateIpAddress'),
                        })
        except Exception as e:
            architecture['ec2_error'] = str(e)
        
        # RDS Databases
        try:
            rds = self._get_client('rds')
            dbs = rds.describe_db_instances()
            for db in dbs.get('DBInstances', []):
                architecture['rds_databases'].append({
                    'id': db['DBInstanceIdentifier'],
                    'engine': db['Engine'],
                    'engine_version': db.get('EngineVersion'),
                    'class': db['DBInstanceClass'],
                    'storage_gb': db.get('AllocatedStorage'),
                    'storage_type': db.get('StorageType'),
                    'multi_az': db.get('MultiAZ', False),
                    'status': db['DBInstanceStatus'],
                })
        except Exception as e:
            architecture['rds_error'] = str(e)
        
        # Lambda Functions
        try:
            lambda_client = self._get_client('lambda')
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page.get('Functions', []):
                    architecture['lambda_functions'].append({
                        'name': func['FunctionName'],
                        'runtime': func.get('Runtime', 'N/A'),
                        'memory_mb': func.get('MemorySize'),
                        'timeout': func.get('Timeout'),
                        'code_size_mb': round(func.get('CodeSize', 0) / 1024 / 1024, 2),
                        'last_modified': func.get('LastModified'),
                    })
        except Exception as e:
            architecture['lambda_error'] = str(e)
        
        # S3 Buckets
        try:
            s3 = self._get_client('s3')
            buckets = s3.list_buckets()
            for bucket in buckets.get('Buckets', []):
                bucket_info = {
                    'name': bucket['Name'],
                    'created': bucket['CreationDate'].isoformat() if bucket.get('CreationDate') else None,
                }
                # Try to get bucket location
                try:
                    location = s3.get_bucket_location(Bucket=bucket['Name'])
                    bucket_info['region'] = location.get('LocationConstraint') or 'us-east-1'
                except:
                    pass
                architecture['s3_buckets'].append(bucket_info)
        except Exception as e:
            architecture['s3_error'] = str(e)
        
        # CloudFront Distributions
        try:
            cf = self._get_client('cloudfront')
            distributions = cf.list_distributions()
            for dist in distributions.get('DistributionList', {}).get('Items', []):
                origins = [o.get('DomainName') for o in dist.get('Origins', {}).get('Items', [])]
                architecture['cloudfront_distributions'].append({
                    'id': dist['Id'],
                    'domain': dist.get('DomainName'),
                    'status': dist.get('Status'),
                    'enabled': dist.get('Enabled'),
                    'origins': origins,
                    'price_class': dist.get('PriceClass'),
                })
        except Exception as e:
            architecture['cloudfront_error'] = str(e)
        
        # ElastiCache Clusters
        try:
            elasticache = self._get_client('elasticache')
            clusters = elasticache.describe_cache_clusters()
            for cluster in clusters.get('CacheClusters', []):
                architecture['elasticache_clusters'].append({
                    'id': cluster['CacheClusterId'],
                    'engine': cluster.get('Engine'),
                    'engine_version': cluster.get('EngineVersion'),
                    'node_type': cluster.get('CacheNodeType'),
                    'num_nodes': cluster.get('NumCacheNodes'),
                    'status': cluster.get('CacheClusterStatus'),
                })
        except Exception as e:
            architecture['elasticache_error'] = str(e)
        
        # API Gateway
        try:
            apigw = self._get_client('apigateway')
            apis = apigw.get_rest_apis()
            for api in apis.get('items', []):
                architecture['api_gateways'].append({
                    'id': api['id'],
                    'name': api['name'],
                    'endpoint_type': api.get('endpointConfiguration', {}).get('types', []),
                })
        except Exception as e:
            architecture['apigateway_error'] = str(e)
        
        # Also check API Gateway V2 (HTTP APIs)
        try:
            apigw2 = self._get_client('apigatewayv2')
            apis = apigw2.get_apis()
            for api in apis.get('Items', []):
                architecture['api_gateways'].append({
                    'id': api['ApiId'],
                    'name': api['Name'],
                    'protocol': api.get('ProtocolType'),
                    'endpoint': api.get('ApiEndpoint'),
                })
        except Exception:
            pass
        
        # Load Balancers (ALB/NLB)
        try:
            elbv2 = self._get_client('elbv2')
            lbs = elbv2.describe_load_balancers()
            for lb in lbs.get('LoadBalancers', []):
                architecture['load_balancers'].append({
                    'name': lb['LoadBalancerName'],
                    'type': lb.get('Type'),
                    'scheme': lb.get('Scheme'),
                    'dns': lb.get('DNSName'),
                    'state': lb.get('State', {}).get('Code'),
                })
        except Exception as e:
            architecture['elb_error'] = str(e)
        
        # ECS Services
        try:
            ecs = self._get_client('ecs')
            clusters = ecs.list_clusters()
            for cluster_arn in clusters.get('clusterArns', []):
                cluster_name = cluster_arn.split('/')[-1]
                services = ecs.list_services(cluster=cluster_arn)
                for svc_arn in services.get('serviceArns', []):
                    svc_details = ecs.describe_services(cluster=cluster_arn, services=[svc_arn])
                    for svc in svc_details.get('services', []):
                        architecture['ecs_services'].append({
                            'cluster': cluster_name,
                            'name': svc['serviceName'],
                            'status': svc.get('status'),
                            'desired_count': svc.get('desiredCount'),
                            'running_count': svc.get('runningCount'),
                            'launch_type': svc.get('launchType'),
                        })
        except Exception as e:
            architecture['ecs_error'] = str(e)
        
        # EKS Clusters
        try:
            eks = self._get_client('eks')
            clusters = eks.list_clusters()
            for cluster_name in clusters.get('clusters', []):
                try:
                    cluster = eks.describe_cluster(name=cluster_name)['cluster']
                    architecture['eks_clusters'].append({
                        'name': cluster_name,
                        'version': cluster.get('version'),
                        'status': cluster.get('status'),
                        'endpoint': cluster.get('endpoint'),
                    })
                except:
                    pass
        except Exception as e:
            architecture['eks_error'] = str(e)
        
        # DynamoDB Tables
        try:
            dynamodb = self._get_client('dynamodb')
            tables = dynamodb.list_tables()
            for table_name in tables.get('TableNames', []):
                try:
                    table = dynamodb.describe_table(TableName=table_name)['Table']
                    architecture['dynamodb_tables'].append({
                        'name': table_name,
                        'status': table.get('TableStatus'),
                        'item_count': table.get('ItemCount'),
                        'size_bytes': table.get('TableSizeBytes'),
                        'billing_mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED'),
                    })
                except:
                    pass
        except Exception as e:
            architecture['dynamodb_error'] = str(e)
        
        # SQS Queues
        try:
            sqs = self._get_client('sqs')
            queues = sqs.list_queues()
            for queue_url in queues.get('QueueUrls', []):
                queue_name = queue_url.split('/')[-1]
                architecture['sqs_queues'].append({
                    'name': queue_name,
                    'url': queue_url,
                })
        except Exception as e:
            architecture['sqs_error'] = str(e)
        
        # SNS Topics
        try:
            sns = self._get_client('sns')
            topics = sns.list_topics()
            for topic in topics.get('Topics', []):
                topic_arn = topic['TopicArn']
                topic_name = topic_arn.split(':')[-1]
                architecture['sns_topics'].append({
                    'name': topic_name,
                    'arn': topic_arn,
                })
        except Exception as e:
            architecture['sns_error'] = str(e)
        
        return architecture
    
    def _format_architecture_summary(self, architecture: Dict[str, Any]) -> str:
        """Format architecture data for AI consumption."""
        summary = f"""
## AWS Architecture Overview (Region: {architecture.get('region', 'unknown')})

"""
        # EC2
        instances = architecture.get('ec2_instances', [])
        if instances:
            summary += f"### EC2 Instances ({len(instances)} total)\n"
            for inst in instances:
                summary += f"- **{inst['name']}** ({inst['id']}): {inst['type']}, State: {inst['state']}\n"
            summary += "\n"
        
        # RDS
        databases = architecture.get('rds_databases', [])
        if databases:
            summary += f"### RDS Databases ({len(databases)} total)\n"
            for db in databases:
                multi_az = "Multi-AZ" if db.get('multi_az') else "Single-AZ"
                summary += f"- **{db['id']}**: {db['engine']} {db.get('engine_version', '')}, {db['class']}, {db.get('storage_gb', '?')}GB {db.get('storage_type', '')}, {multi_az}\n"
            summary += "\n"
        
        # Lambda
        functions = architecture.get('lambda_functions', [])
        if functions:
            summary += f"### Lambda Functions ({len(functions)} total)\n"
            for func in functions[:15]:  # Limit to avoid token overflow
                summary += f"- **{func['name']}**: {func.get('runtime', 'N/A')}, {func.get('memory_mb', '?')}MB, {func.get('timeout', '?')}s timeout\n"
            if len(functions) > 15:
                summary += f"- ... and {len(functions) - 15} more functions\n"
            summary += "\n"
        
        # S3
        buckets = architecture.get('s3_buckets', [])
        if buckets:
            summary += f"### S3 Buckets ({len(buckets)} total)\n"
            for bucket in buckets[:10]:
                summary += f"- {bucket['name']}\n"
            if len(buckets) > 10:
                summary += f"- ... and {len(buckets) - 10} more buckets\n"
            summary += "\n"
        
        # CloudFront
        distributions = architecture.get('cloudfront_distributions', [])
        if distributions:
            summary += f"### CloudFront Distributions ({len(distributions)} total)\n"
            for dist in distributions:
                origins_str = ', '.join(dist.get('origins', [])[:2])
                summary += f"- **{dist['id']}**: {dist.get('domain', 'N/A')}, Price Class: {dist.get('price_class', 'N/A')}, Origins: {origins_str}\n"
            summary += "\n"
        
        # ElastiCache
        clusters = architecture.get('elasticache_clusters', [])
        if clusters:
            summary += f"### ElastiCache Clusters ({len(clusters)} total)\n"
            for cluster in clusters:
                summary += f"- **{cluster['id']}**: {cluster.get('engine', 'N/A')} {cluster.get('engine_version', '')}, {cluster.get('node_type', 'N/A')}, {cluster.get('num_nodes', '?')} nodes\n"
            summary += "\n"
        
        # API Gateway
        apis = architecture.get('api_gateways', [])
        if apis:
            summary += f"### API Gateways ({len(apis)} total)\n"
            for api in apis:
                summary += f"- **{api['name']}** ({api['id']})\n"
            summary += "\n"
        
        # Load Balancers
        lbs = architecture.get('load_balancers', [])
        if lbs:
            summary += f"### Load Balancers ({len(lbs)} total)\n"
            for lb in lbs:
                summary += f"- **{lb['name']}**: {lb.get('type', 'N/A')}, {lb.get('scheme', 'N/A')}\n"
            summary += "\n"
        
        # ECS
        services = architecture.get('ecs_services', [])
        if services:
            summary += f"### ECS Services ({len(services)} total)\n"
            for svc in services:
                summary += f"- **{svc['name']}** (Cluster: {svc['cluster']}): {svc.get('running_count', 0)}/{svc.get('desired_count', 0)} tasks, {svc.get('launch_type', 'N/A')}\n"
            summary += "\n"
        
        # EKS
        eks_clusters = architecture.get('eks_clusters', [])
        if eks_clusters:
            summary += f"### EKS Clusters ({len(eks_clusters)} total)\n"
            for cluster in eks_clusters:
                summary += f"- **{cluster['name']}**: v{cluster.get('version', 'N/A')}, Status: {cluster.get('status', 'N/A')}\n"
            summary += "\n"
        
        # DynamoDB
        tables = architecture.get('dynamodb_tables', [])
        if tables:
            summary += f"### DynamoDB Tables ({len(tables)} total)\n"
            for table in tables:
                size_mb = round(table.get('size_bytes', 0) / 1024 / 1024, 2)
                summary += f"- **{table['name']}**: {table.get('item_count', 0):,} items, {size_mb}MB, {table.get('billing_mode', 'N/A')}\n"
            summary += "\n"
        
        # SQS
        queues = architecture.get('sqs_queues', [])
        if queues:
            summary += f"### SQS Queues ({len(queues)} total)\n"
            for queue in queues:
                summary += f"- {queue['name']}\n"
            summary += "\n"
        
        # SNS
        topics = architecture.get('sns_topics', [])
        if topics:
            summary += f"### SNS Topics ({len(topics)} total)\n"
            for topic in topics:
                summary += f"- {topic['name']}\n"
            summary += "\n"
        
        return summary

    def analyze_costs_with_ai(self, cost_data: Dict[str, Any], architecture: Optional[Dict[str, Any]] = None) -> str:
        """
        Use AI to analyze cost data and provide insights and recommendations.
        Now includes architecture context for better recommendations.
        
        Args:
            cost_data: Dictionary containing cost summary and breakdown
            architecture: Optional dictionary with AWS resource inventory
            
        Returns:
            AI-generated analysis and recommendations
        """
        if not self.openai_client:
            return "AI analysis unavailable - OpenAI API key not configured."
        
        # Prepare the cost summary for AI
        cost_summary = f"""
# AWS Cost Analysis Data

## Billing Summary
- **Period**: {cost_data.get('period_days', 30)} days ({cost_data.get('start_date')} to {cost_data.get('end_date')})
- **Total Cost**: ${cost_data.get('total_cost', 0):,.2f} {cost_data.get('currency', 'USD')}
- **Average Daily Cost**: ${cost_data.get('avg_daily_cost', 0):,.2f}

## Cost by Service (Top 10)
"""
        for svc in cost_data.get('service_breakdown', [])[:10]:
            pct = (svc['cost'] / cost_data.get('total_cost', 1) * 100) if cost_data.get('total_cost', 0) > 0 else 0
            cost_summary += f"- {svc['service']}: ${svc['cost']:,.2f} ({pct:.1f}%)\n"
        
        # Add forecast if available
        forecast = cost_data.get('forecast', {})
        if forecast and not forecast.get('error'):
            cost_summary += f"\n## 30-Day Forecast\n- Projected Cost: ${forecast.get('forecasted_total', 0):,.2f}\n"
        
        # Add cost changes if available
        changes = cost_data.get('cost_changes', {})
        if changes and changes.get('changes'):
            cost_summary += "\n## Cost Changes (vs Previous Period)\n"
            for change in changes['changes'][:7]:
                direction = "📈" if change['change_amount'] > 0 else "📉"
                cost_summary += f"- {direction} {change['service']}: ${change['change_amount']:+,.2f} ({change['change_percent']:+.1f}%)\n"
        
        # Add anomalies if detected
        anomalies = cost_data.get('anomalies', [])
        if anomalies and not any(a.get('error') for a in anomalies):
            cost_summary += f"\n## Cost Anomalies\n- Detected {len(anomalies)} cost anomalies in the period.\n"
        
        # Add architecture context if available
        if architecture:
            cost_summary += "\n" + self._format_architecture_summary(architecture)
        
        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": """You are a senior AWS Solutions Architect and FinOps consultant with 10+ years of experience in cloud cost optimization.
You have been provided with both detailed cost data AND the actual AWS architecture inventory.

Provide a comprehensive, detailed AWS Cost Optimization Report with the following structure:

# AWS Cost Optimization Report

## Executive Summary
Write a clear 3-4 sentence executive overview covering:
- Total monthly spend and trend direction
- Primary cost drivers
- Potential savings opportunity (estimate a realistic range)

## Architecture Analysis
Provide detailed assessment:
- **Current State**: Describe the architecture based on discovered resources
- **Cost Efficiency Assessment**: Is this architecture appropriate for its likely purpose?
- **Over-provisioning**: Identify specific resources that appear oversized
- **Under-utilization**: Flag resources that may not be fully utilized
- **Architecture Recommendations**: Suggest structural changes (e.g., serverless migration, consolidation)

## Service-Specific Recommendations
For EACH major cost-driving service, provide:

### [Service Name] (Current: $X.XX/month)
- **Current Configuration**: What's being used
- **Issue Identified**: Specific problem
- **Recommendation**: Concrete action to take
- **Estimated Monthly Savings**: $X.XX
- **Implementation Effort**: Low/Medium/High

Include at minimum: EC2, RDS, Lambda, S3, CloudFront, VPC, ECS (if applicable)

## Quick Wins (Immediate Actions)
List 3-5 actions that can be implemented TODAY with:
- Specific action item
- Estimated savings
- Risk level

## Medium-Term Optimizations
List 3-5 optimizations requiring 1-4 weeks of planning:
- What needs to change
- Why it will save money
- Estimated savings
- Prerequisites or dependencies

## Long-Term Strategic Recommendations
Suggest 2-3 strategic changes for 6-12 month planning:
- Reserved Instances / Savings Plans analysis
- Architecture modernization opportunities
- Cost governance improvements

## Cost Anomalies & Alerts
- Flag any unusual spending patterns
- Identify potential orphaned resources
- Note services with unexpected growth (>50% month-over-month)

## Prioritized Action Items
Provide a numbered list (1-10) of recommended actions:
1. [Action] - Est. Savings: $X/month - Effort: [Low/Med/High] - Priority: [Critical/High/Medium]
...

## Total Estimated Savings
- **Quick Wins**: $X.XX/month
- **Medium-Term**: $X.XX/month
- **Long-Term**: $X.XX/month
- **TOTAL POTENTIAL SAVINGS**: $X.XX/month (X% of current spend)

---
IMPORTANT RULES:
- Always include specific dollar amounts for estimated savings
- Reference actual resource names/IDs from the architecture data
- Be conservative but realistic with savings estimates
- Acknowledge any assumptions made
- Format using proper markdown with headers, bullet points, and bold text"""
                    },
                    {
                        "role": "user",
                        "content": f"Analyze this AWS cost and architecture data. Provide a detailed, actionable optimization report:\n\n{cost_summary}"
                    }
                ],
                max_tokens=4000,
                temperature=0.2
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            return f"AI analysis failed: {str(e)}"
    
    def get_comprehensive_analysis(self, days: int = 30, include_architecture: bool = True) -> Dict[str, Any]:
        """
        Get a comprehensive cost analysis including all available data.
        
        Args:
            days: Number of days to analyze
            include_architecture: Whether to discover and include architecture info
            
        Returns:
            Dictionary with all cost data and AI analysis
        """
        # Gather all cost data
        cost_summary = self.get_cost_summary(days)
        cost_summary['forecast'] = self.get_cost_forecast(30)
        cost_summary['cost_changes'] = self.get_top_cost_changes(days)
        cost_summary['anomalies'] = self.get_cost_anomalies(days)
        
        # Discover architecture if requested
        architecture = None
        if include_architecture:
            architecture = self.discover_architecture()
            cost_summary['architecture'] = architecture
        
        # Add AI analysis with architecture context
        cost_summary['ai_analysis'] = self.analyze_costs_with_ai(cost_summary, architecture)
        
        return cost_summary
