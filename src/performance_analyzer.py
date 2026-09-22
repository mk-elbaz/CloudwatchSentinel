"""
AWS Performance Analyzer with AI-powered insights.
Analyzes Lambda cold starts, RDS Performance Insights, EC2 metrics, and API Gateway latency.
"""

import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from openai import OpenAI
import os
import json
from botocore.exceptions import ClientError, NoCredentialsError
from collections import defaultdict


class AWSPerformanceAnalyzer:
    """Analyzes AWS performance metrics and provides AI-powered optimization recommendations."""
    
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
            else:
                self.service_status[service_name] = f"Error: {error_code}"
            return None
        except NoCredentialsError:
            self.service_status[service_name] = "No AWS credentials configured"
            return None
        except Exception as e:
            self.service_status[service_name] = f"Error: {str(e)}"
            return None
    
    def test_connection(self) -> Dict[str, bool]:
        """Test connectivity to performance-related AWS services."""
        results = {}
        
        # Test Lambda
        try:
            lambda_client = self._get_client('lambda')
            if lambda_client:
                lambda_client.list_functions(MaxItems=1)
                results['lambda'] = True
        except Exception:
            results['lambda'] = False
        
        # Test CloudWatch
        try:
            cw = self._get_client('cloudwatch')
            if cw:
                cw.list_metrics(Limit=1)
                results['cloudwatch'] = True
        except Exception:
            results['cloudwatch'] = False
        
        # Test RDS
        try:
            rds = self._get_client('rds')
            if rds:
                rds.describe_db_instances(MaxRecords=20)
                results['rds'] = True
        except Exception:
            results['rds'] = False
        
        # Test API Gateway
        try:
            apigw = self._get_client('apigateway')
            if apigw:
                apigw.get_rest_apis(limit=1)
                results['apigateway'] = True
        except Exception:
            results['apigateway'] = False
        
        return results
    
    def analyze_lambda_cold_starts(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze Lambda function cold starts and provide optimization suggestions."""
        insights = []
        lambda_client = self._get_client('lambda')
        cw = self._get_client('cloudwatch')
        logs = self._get_client('logs')
        
        if not lambda_client or not cw:
            return {'insights': insights, 'error': 'Lambda or CloudWatch client unavailable'}
        
        # Get list of Lambda functions
        functions_response = self._safe_api_call('lambda', lambda_client.list_functions)
        if not functions_response:
            return {'insights': insights, 'error': 'Could not list Lambda functions'}
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        for func in functions_response.get('Functions', []):
            func_name = func['FunctionName']
            runtime = func.get('Runtime', 'Unknown')
            memory = func.get('MemorySize', 128)
            timeout = func.get('Timeout', 3)
            code_size = func.get('CodeSize', 0)
            
            # Get invocation metrics
            try:
                invocations = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Sum']
                )
                total_invocations = sum(dp['Sum'] for dp in invocations.get('Datapoints', []))
                
                # Get duration metrics
                duration = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Duration',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Average', 'Maximum', 'Minimum']
                )
                
                avg_duration = 0
                max_duration = 0
                if duration.get('Datapoints'):
                    avg_duration = sum(dp['Average'] for dp in duration['Datapoints']) / len(duration['Datapoints'])
                    max_duration = max(dp['Maximum'] for dp in duration['Datapoints'])
                
                # Get error metrics
                errors = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Errors',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Sum']
                )
                total_errors = sum(dp['Sum'] for dp in errors.get('Datapoints', []))
                
                # Get concurrent executions
                concurrency = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='ConcurrentExecutions',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600,
                    Statistics=['Maximum']
                )
                max_concurrency = max((dp['Maximum'] for dp in concurrency.get('Datapoints', [])), default=0)
                
                # Calculate cold start estimate (based on duration variance)
                cold_start_ratio = 0
                if max_duration > 0 and avg_duration > 0:
                    # High max/avg ratio suggests cold starts
                    cold_start_ratio = (max_duration - avg_duration) / max_duration if max_duration > avg_duration else 0
                
                insight = {
                    'function_name': func_name,
                    'runtime': runtime,
                    'memory_mb': memory,
                    'timeout_sec': timeout,
                    'code_size_mb': round(code_size / (1024 * 1024), 2),
                    'total_invocations': int(total_invocations),
                    'avg_duration_ms': round(avg_duration, 2),
                    'max_duration_ms': round(max_duration, 2),
                    'total_errors': int(total_errors),
                    'error_rate': round((total_errors / total_invocations * 100) if total_invocations > 0 else 0, 2),
                    'max_concurrency': int(max_concurrency),
                    'cold_start_likelihood': 'HIGH' if cold_start_ratio > 0.5 else 'MEDIUM' if cold_start_ratio > 0.3 else 'LOW',
                    'recommendations': []
                }
                
                # Generate recommendations
                if cold_start_ratio > 0.5:
                    insight['recommendations'].append({
                        'type': 'COLD_START',
                        'severity': 'HIGH',
                        'message': 'High cold start ratio detected',
                        'suggestion': 'Consider enabling Provisioned Concurrency or using Lambda SnapStart (for Java)'
                    })
                
                if runtime in ['python3.8', 'python3.9', 'nodejs14.x', 'nodejs16.x']:
                    insight['recommendations'].append({
                        'type': 'RUNTIME_UPDATE',
                        'severity': 'MEDIUM',
                        'message': f'Runtime {runtime} may be outdated',
                        'suggestion': 'Consider upgrading to a newer runtime version for better performance'
                    })
                
                if code_size > 50 * 1024 * 1024:  # > 50MB
                    insight['recommendations'].append({
                        'type': 'PACKAGE_SIZE',
                        'severity': 'MEDIUM',
                        'message': f'Large deployment package ({insight["code_size_mb"]}MB)',
                        'suggestion': 'Reduce package size by removing unused dependencies or using Lambda layers'
                    })
                
                if memory < 512 and avg_duration > timeout * 1000 * 0.8:
                    insight['recommendations'].append({
                        'type': 'MEMORY_CPU',
                        'severity': 'MEDIUM',
                        'message': 'Function may be CPU-bound with low memory allocation',
                        'suggestion': 'Increase memory allocation to get proportionally more CPU'
                    })
                
                if total_errors > 0 and (total_errors / max(total_invocations, 1)) > 0.05:
                    insight['recommendations'].append({
                        'type': 'ERROR_RATE',
                        'severity': 'HIGH',
                        'message': f'High error rate ({insight["error_rate"]}%)',
                        'suggestion': 'Review CloudWatch Logs and implement better error handling'
                    })
                
                insights.append(insight)
                
            except ClientError as e:
                self.service_status[f'lambda_{func_name}'] = f"Error: {e}"
        
        # Sort by invocations (most active first)
        insights.sort(key=lambda x: x['total_invocations'], reverse=True)
        
        return {
            'insights': insights,
            'analysis_period_hours': hours,
            'total_functions': len(insights),
            'functions_with_issues': len([i for i in insights if i['recommendations']])
        }
    
    def analyze_rds_performance(self) -> Dict[str, Any]:
        """Analyze RDS instance performance using Performance Insights."""
        insights = []
        rds = self._get_client('rds')
        pi = self._get_client('pi')
        cw = self._get_client('cloudwatch')
        
        if not rds or not cw:
            return {'insights': insights, 'error': 'RDS or CloudWatch client unavailable'}
        
        # Get RDS instances
        response = self._safe_api_call('rds', rds.describe_db_instances)
        if not response:
            return {'insights': insights, 'error': 'Could not describe RDS instances'}
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        for instance in response.get('DBInstances', []):
            db_id = instance['DBInstanceIdentifier']
            engine = instance.get('Engine', 'Unknown')
            instance_class = instance.get('DBInstanceClass', 'Unknown')
            storage_type = instance.get('StorageType', 'Unknown')
            allocated_storage = instance.get('AllocatedStorage', 0)
            multi_az = instance.get('MultiAZ', False)
            status = instance.get('DBInstanceStatus', 'Unknown')
            
            insight = {
                'db_identifier': db_id,
                'engine': engine,
                'instance_class': instance_class,
                'storage_type': storage_type,
                'allocated_storage_gb': allocated_storage,
                'multi_az': multi_az,
                'status': status,
                'metrics': {},
                'recommendations': []
            }
            
            # Get CloudWatch metrics
            metric_queries = [
                ('CPUUtilization', 'Average'),
                ('DatabaseConnections', 'Average'),
                ('FreeableMemory', 'Average'),
                ('ReadIOPS', 'Average'),
                ('WriteIOPS', 'Average'),
                ('ReadLatency', 'Average'),
                ('WriteLatency', 'Average'),
                ('FreeStorageSpace', 'Average'),
                ('DiskQueueDepth', 'Average')
            ]
            
            for metric_name, stat in metric_queries:
                try:
                    metric = cw.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName=metric_name,
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                        StartTime=start_time,
                        EndTime=end_time,
                        Period=3600,
                        Statistics=[stat]
                    )
                    
                    if metric.get('Datapoints'):
                        values = [dp[stat] for dp in metric['Datapoints']]
                        insight['metrics'][metric_name] = {
                            'average': round(sum(values) / len(values), 2),
                            'max': round(max(values), 2),
                            'min': round(min(values), 2)
                        }
                except ClientError:
                    pass
            
            # Analyze metrics and generate recommendations
            cpu = insight['metrics'].get('CPUUtilization', {})
            if cpu.get('average', 0) > 80:
                insight['recommendations'].append({
                    'type': 'HIGH_CPU',
                    'severity': 'HIGH',
                    'message': f'High average CPU utilization ({cpu["average"]}%)',
                    'suggestion': 'Consider upgrading instance class or optimizing queries'
                })
            
            memory = insight['metrics'].get('FreeableMemory', {})
            if memory.get('average', float('inf')) < 500 * 1024 * 1024:  # Less than 500MB
                insight['recommendations'].append({
                    'type': 'LOW_MEMORY',
                    'severity': 'HIGH',
                    'message': 'Low freeable memory',
                    'suggestion': 'Upgrade to an instance class with more memory or optimize queries'
                })
            
            storage = insight['metrics'].get('FreeStorageSpace', {})
            if allocated_storage > 0:
                free_pct = (storage.get('average', 0) / (allocated_storage * 1024 * 1024 * 1024)) * 100
                if free_pct < 20:
                    insight['recommendations'].append({
                        'type': 'LOW_STORAGE',
                        'severity': 'MEDIUM' if free_pct > 10 else 'HIGH',
                        'message': f'Low free storage space ({round(free_pct, 1)}% free)',
                        'suggestion': 'Increase allocated storage or clean up unused data'
                    })
            
            read_latency = insight['metrics'].get('ReadLatency', {})
            write_latency = insight['metrics'].get('WriteLatency', {})
            if read_latency.get('average', 0) > 0.02 or write_latency.get('average', 0) > 0.02:
                insight['recommendations'].append({
                    'type': 'HIGH_LATENCY',
                    'severity': 'MEDIUM',
                    'message': 'High I/O latency detected',
                    'suggestion': 'Consider upgrading to Provisioned IOPS storage or optimizing queries'
                })
            
            disk_queue = insight['metrics'].get('DiskQueueDepth', {})
            if disk_queue.get('average', 0) > 5:
                insight['recommendations'].append({
                    'type': 'DISK_QUEUE',
                    'severity': 'MEDIUM',
                    'message': f'High disk queue depth ({disk_queue["average"]})',
                    'suggestion': 'Storage is bottlenecked - upgrade IOPS or optimize workload'
                })
            
            # Performance Insights analysis if available
            if pi and instance.get('PerformanceInsightsEnabled', False):
                try:
                    resource_arn = instance['DBInstanceArn']
                    pi_data = pi.get_resource_metrics(
                        ServiceType='RDS',
                        Identifier=resource_arn,
                        MetricQueries=[
                            {'Metric': 'db.load.avg'},
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                        PeriodInSeconds=3600
                    )
                    insight['performance_insights_enabled'] = True
                    insight['db_load'] = pi_data
                except ClientError:
                    insight['performance_insights_enabled'] = False
            else:
                insight['performance_insights_enabled'] = False
                if status == 'available':
                    insight['recommendations'].append({
                        'type': 'ENABLE_PI',
                        'severity': 'LOW',
                        'message': 'Performance Insights is not enabled',
                        'suggestion': 'Enable Performance Insights for detailed query-level performance analysis'
                    })
            
            insights.append(insight)
        
        return {
            'insights': insights,
            'total_instances': len(insights),
            'instances_with_issues': len([i for i in insights if i['recommendations']])
        }
    
    def analyze_ec2_performance(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze EC2 instance performance metrics."""
        insights = []
        ec2 = self._get_client('ec2')
        cw = self._get_client('cloudwatch')
        
        if not ec2 or not cw:
            return {'insights': insights, 'error': 'EC2 or CloudWatch client unavailable'}
        
        # Get running EC2 instances
        response = self._safe_api_call('ec2', ec2.describe_instances,
                                       Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        if not response:
            return {'insights': insights, 'error': 'Could not describe EC2 instances'}
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_id = instance['InstanceId']
                instance_type = instance.get('InstanceType', 'Unknown')
                
                # Get instance name from tags
                instance_name = instance_id
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                
                insight = {
                    'instance_id': instance_id,
                    'instance_name': instance_name,
                    'instance_type': instance_type,
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'Unknown'),
                    'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                    'metrics': {},
                    'recommendations': []
                }
                
                # Get CloudWatch metrics
                metrics_to_fetch = [
                    ('CPUUtilization', 'Percent'),
                    ('NetworkIn', 'Bytes'),
                    ('NetworkOut', 'Bytes'),
                    ('DiskReadOps', 'Count'),
                    ('DiskWriteOps', 'Count'),
                    ('StatusCheckFailed', 'Count')
                ]
                
                for metric_name, unit in metrics_to_fetch:
                    try:
                        metric = cw.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName=metric_name,
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,
                            Statistics=['Average', 'Maximum']
                        )
                        
                        if metric.get('Datapoints'):
                            avg_values = [dp['Average'] for dp in metric['Datapoints']]
                            max_values = [dp['Maximum'] for dp in metric['Datapoints']]
                            insight['metrics'][metric_name] = {
                                'average': round(sum(avg_values) / len(avg_values), 2),
                                'max': round(max(max_values), 2)
                            }
                    except ClientError:
                        pass
                
                # Generate recommendations
                cpu = insight['metrics'].get('CPUUtilization', {})
                if cpu.get('average', 0) < 10 and cpu.get('max', 0) < 30:
                    insight['recommendations'].append({
                        'type': 'UNDERUTILIZED',
                        'severity': 'MEDIUM',
                        'message': f'Instance appears underutilized (avg CPU: {cpu.get("average", 0)}%)',
                        'suggestion': 'Consider downsizing to a smaller instance type to reduce costs'
                    })
                elif cpu.get('average', 0) > 80:
                    insight['recommendations'].append({
                        'type': 'HIGH_CPU',
                        'severity': 'HIGH',
                        'message': f'High CPU utilization (avg: {cpu["average"]}%)',
                        'suggestion': 'Consider upgrading to a larger instance type or optimizing workload'
                    })
                
                status_check = insight['metrics'].get('StatusCheckFailed', {})
                if status_check.get('max', 0) > 0:
                    insight['recommendations'].append({
                        'type': 'STATUS_CHECK_FAILED',
                        'severity': 'HIGH',
                        'message': 'Instance had status check failures',
                        'suggestion': 'Investigate instance health and consider recovery options'
                    })
                
                # Check for burstable instance performance
                if instance_type.startswith('t'):
                    insight['recommendations'].append({
                        'type': 'BURSTABLE_INSTANCE',
                        'severity': 'INFO',
                        'message': 'Using burstable instance type',
                        'suggestion': 'Monitor CPU credit balance to ensure sustained performance'
                    })
                
                insights.append(insight)
        
        return {
            'insights': insights,
            'analysis_period_hours': hours,
            'total_instances': len(insights),
            'instances_with_issues': len([i for i in insights if 
                                          any(r['severity'] in ['HIGH', 'MEDIUM'] for r in i['recommendations'])])
        }
    
    def analyze_api_gateway_latency(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze API Gateway latency and error rates."""
        insights = []
        apigw = self._get_client('apigateway')
        apigwv2 = self._get_client('apigatewayv2')
        cw = self._get_client('cloudwatch')
        
        if not cw:
            return {'insights': insights, 'error': 'CloudWatch client unavailable'}
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # Analyze REST APIs
        if apigw:
            apis_response = self._safe_api_call('apigateway', apigw.get_rest_apis)
            if apis_response:
                for api in apis_response.get('items', []):
                    api_id = api['id']
                    api_name = api.get('name', api_id)
                    
                    insight = {
                        'api_id': api_id,
                        'api_name': api_name,
                        'api_type': 'REST',
                        'metrics': {},
                        'recommendations': []
                    }
                    
                    # Get metrics
                    metrics_to_fetch = [
                        ('Count', 'Sum'),
                        ('Latency', 'Average'),
                        ('IntegrationLatency', 'Average'),
                        ('4XXError', 'Sum'),
                        ('5XXError', 'Sum')
                    ]
                    
                    for metric_name, stat in metrics_to_fetch:
                        try:
                            metric = cw.get_metric_statistics(
                                Namespace='AWS/ApiGateway',
                                MetricName=metric_name,
                                Dimensions=[{'Name': 'ApiName', 'Value': api_name}],
                                StartTime=start_time,
                                EndTime=end_time,
                                Period=3600,
                                Statistics=[stat, 'Maximum'] if stat == 'Average' else [stat]
                            )
                            
                            if metric.get('Datapoints'):
                                if stat == 'Sum':
                                    insight['metrics'][metric_name] = {
                                        'total': sum(dp[stat] for dp in metric['Datapoints'])
                                    }
                                else:
                                    values = [dp[stat] for dp in metric['Datapoints']]
                                    max_values = [dp.get('Maximum', dp[stat]) for dp in metric['Datapoints']]
                                    insight['metrics'][metric_name] = {
                                        'average': round(sum(values) / len(values), 2),
                                        'max': round(max(max_values), 2)
                                    }
                        except ClientError:
                            pass
                    
                    # Generate recommendations
                    latency = insight['metrics'].get('Latency', {})
                    integration_latency = insight['metrics'].get('IntegrationLatency', {})
                    
                    if latency.get('average', 0) > 1000:  # > 1 second
                        insight['recommendations'].append({
                            'type': 'HIGH_LATENCY',
                            'severity': 'HIGH',
                            'message': f'High average latency ({latency["average"]}ms)',
                            'suggestion': 'Optimize backend integration, consider caching, or review Lambda cold starts'
                        })
                    
                    if integration_latency.get('average', 0) > 500:
                        insight['recommendations'].append({
                            'type': 'HIGH_INTEGRATION_LATENCY',
                            'severity': 'MEDIUM',
                            'message': f'High integration latency ({integration_latency["average"]}ms)',
                            'suggestion': 'Optimize backend service response time'
                        })
                    
                    # Calculate overhead (API Gateway processing time)
                    if latency.get('average') and integration_latency.get('average'):
                        overhead = latency['average'] - integration_latency['average']
                        if overhead > 100:
                            insight['recommendations'].append({
                                'type': 'HIGH_OVERHEAD',
                                'severity': 'LOW',
                                'message': f'API Gateway overhead is {round(overhead)}ms',
                                'suggestion': 'Review request/response transformations and authorizers'
                            })
                    
                    total_requests = insight['metrics'].get('Count', {}).get('total', 0)
                    errors_4xx = insight['metrics'].get('4XXError', {}).get('total', 0)
                    errors_5xx = insight['metrics'].get('5XXError', {}).get('total', 0)
                    
                    if total_requests > 0:
                        error_rate_4xx = (errors_4xx / total_requests) * 100
                        error_rate_5xx = (errors_5xx / total_requests) * 100
                        
                        if error_rate_5xx > 1:
                            insight['recommendations'].append({
                                'type': 'HIGH_5XX_ERRORS',
                                'severity': 'HIGH',
                                'message': f'High 5XX error rate ({round(error_rate_5xx, 2)}%)',
                                'suggestion': 'Investigate backend errors and implement proper error handling'
                            })
                        
                        if error_rate_4xx > 10:
                            insight['recommendations'].append({
                                'type': 'HIGH_4XX_ERRORS',
                                'severity': 'MEDIUM',
                                'message': f'High 4XX error rate ({round(error_rate_4xx, 2)}%)',
                                'suggestion': 'Review API documentation and client implementations'
                            })
                    
                    insights.append(insight)
        
        # Analyze HTTP APIs (API Gateway v2)
        if apigwv2:
            http_apis_response = self._safe_api_call('apigatewayv2', apigwv2.get_apis)
            if http_apis_response:
                for api in http_apis_response.get('Items', []):
                    api_id = api['ApiId']
                    api_name = api.get('Name', api_id)
                    protocol = api.get('ProtocolType', 'HTTP')
                    
                    insight = {
                        'api_id': api_id,
                        'api_name': api_name,
                        'api_type': protocol,
                        'metrics': {},
                        'recommendations': []
                    }
                    
                    # Similar metrics collection for HTTP APIs
                    try:
                        count_metric = cw.get_metric_statistics(
                            Namespace='AWS/ApiGateway',
                            MetricName='Count',
                            Dimensions=[{'Name': 'ApiId', 'Value': api_id}],
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,
                            Statistics=['Sum']
                        )
                        if count_metric.get('Datapoints'):
                            insight['metrics']['Count'] = {
                                'total': sum(dp['Sum'] for dp in count_metric['Datapoints'])
                            }
                    except ClientError:
                        pass
                    
                    insights.append(insight)
        
        return {
            'insights': insights,
            'analysis_period_hours': hours,
            'total_apis': len(insights),
            'apis_with_issues': len([i for i in insights if i['recommendations']])
        }
    
    def run_full_analysis(self, hours: int = 24) -> Dict[str, Any]:
        """Run comprehensive performance analysis across all services."""
        self.service_status = {}  # Reset status
        
        results = {
            'analysis_time': datetime.now().isoformat(),
            'analysis_period_hours': hours,
            'lambda': self.analyze_lambda_cold_starts(hours),
            'rds': self.analyze_rds_performance(),
            'ec2': self.analyze_ec2_performance(hours),
            'api_gateway': self.analyze_api_gateway_latency(hours),
            'service_status': self.service_status
        }
        
        # Calculate overall summary
        total_issues = (
            results['lambda'].get('functions_with_issues', 0) +
            results['rds'].get('instances_with_issues', 0) +
            results['ec2'].get('instances_with_issues', 0) +
            results['api_gateway'].get('apis_with_issues', 0)
        )
        
        results['summary'] = {
            'total_resources_analyzed': (
                results['lambda'].get('total_functions', 0) +
                results['rds'].get('total_instances', 0) +
                results['ec2'].get('total_instances', 0) +
                results['api_gateway'].get('total_apis', 0)
            ),
            'resources_with_issues': total_issues,
            'services_analyzed': ['Lambda', 'RDS', 'EC2', 'API Gateway']
        }
        
        return results
    
    def get_ai_recommendations(self, analysis_results: Dict[str, Any]) -> Optional[str]:
        """Get AI-powered performance optimization recommendations."""
        if not self.openai_client:
            return None
        
        # Prepare summary for AI
        summary = {
            'lambda': analysis_results.get('lambda', {}).get('insights', [])[:10],
            'rds': analysis_results.get('rds', {}).get('insights', [])[:5],
            'ec2': analysis_results.get('ec2', {}).get('insights', [])[:10],
            'api_gateway': analysis_results.get('api_gateway', {}).get('insights', [])[:5]
        }
        
        system_prompt = """You are an AWS performance optimization expert. Analyze the performance metrics and provide:

1. **Executive Summary**: Overall performance health assessment
2. **Critical Bottlenecks**: Immediate performance issues requiring attention
3. **Optimization Priorities**: Ranked list of improvements by impact
4. **Cost-Performance Tradeoffs**: Balance between performance and cost
5. **Architecture Recommendations**: Structural improvements for better performance

Focus on:
- Lambda cold start optimization strategies
- Database query and connection optimization
- Compute right-sizing recommendations
- API response time improvements

Format your response in clear Markdown with headers and bullet points.
Be specific with numbers and actionable recommendations."""

        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze these AWS performance metrics:\n\n{json.dumps(summary, indent=2, default=str)}"}
                ],
                max_tokens=2000,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating AI recommendations: {str(e)}"
    
    def get_performance_score(self, analysis_results: Dict[str, Any]) -> int:
        """Calculate a performance score from 0-100."""
        score = 100
        
        # Deduct points for issues
        for service in ['lambda', 'rds', 'ec2', 'api_gateway']:
            insights = analysis_results.get(service, {}).get('insights', [])
            for insight in insights:
                for rec in insight.get('recommendations', []):
                    severity = rec.get('severity', 'LOW')
                    if severity == 'HIGH':
                        score -= 10
                    elif severity == 'MEDIUM':
                        score -= 5
                    elif severity == 'LOW':
                        score -= 2
        
        return max(0, score)
