"""
AWS Resource Health Dashboard.
Aggregates CloudWatch Alarms, EC2/RDS health checks, Lambda errors, and computes health scores.
"""

import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from openai import OpenAI
import os
import json
from botocore.exceptions import ClientError, NoCredentialsError
from collections import defaultdict


class AWSHealthDashboard:
    """Monitors AWS resource health and provides automated health scores."""
    
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
    
    def get_cloudwatch_alarms_status(self) -> Dict[str, Any]:
        """Get overview of all CloudWatch alarms and their current states."""
        cw = self._get_client('cloudwatch')
        if not cw:
            return {'alarms': [], 'error': 'CloudWatch client unavailable'}
        
        alarms = []
        alarm_summary = {
            'OK': 0,
            'ALARM': 0,
            'INSUFFICIENT_DATA': 0
        }
        
        # Get all alarms with pagination
        paginator = cw.get_paginator('describe_alarms')
        try:
            for page in paginator.paginate():
                for alarm in page.get('MetricAlarms', []):
                    state = alarm.get('StateValue', 'UNKNOWN')
                    alarm_summary[state] = alarm_summary.get(state, 0) + 1
                    
                    alarms.append({
                        'name': alarm['AlarmName'],
                        'state': state,
                        'metric_name': alarm.get('MetricName', 'Unknown'),
                        'namespace': alarm.get('Namespace', 'Unknown'),
                        'description': alarm.get('AlarmDescription', ''),
                        'state_reason': alarm.get('StateReason', ''),
                        'state_updated': alarm.get('StateUpdatedTimestamp', '').isoformat() if alarm.get('StateUpdatedTimestamp') else None,
                        'dimensions': {d['Name']: d['Value'] for d in alarm.get('Dimensions', [])},
                        'threshold': alarm.get('Threshold'),
                        'comparison_operator': alarm.get('ComparisonOperator'),
                        'evaluation_periods': alarm.get('EvaluationPeriods'),
                        'actions_enabled': alarm.get('ActionsEnabled', False)
                    })
                
                # Also get composite alarms
                for alarm in page.get('CompositeAlarms', []):
                    state = alarm.get('StateValue', 'UNKNOWN')
                    alarm_summary[state] = alarm_summary.get(state, 0) + 1
                    
                    alarms.append({
                        'name': alarm['AlarmName'],
                        'state': state,
                        'type': 'composite',
                        'description': alarm.get('AlarmDescription', ''),
                        'state_reason': alarm.get('StateReason', ''),
                        'state_updated': alarm.get('StateUpdatedTimestamp', '').isoformat() if alarm.get('StateUpdatedTimestamp') else None,
                        'actions_enabled': alarm.get('ActionsEnabled', False)
                    })
        except ClientError as e:
            self.service_status['cloudwatch_alarms'] = f"Error: {e}"
        
        # Sort by state (ALARM first, then INSUFFICIENT_DATA, then OK)
        state_order = {'ALARM': 0, 'INSUFFICIENT_DATA': 1, 'OK': 2}
        alarms.sort(key=lambda x: state_order.get(x['state'], 3))
        
        return {
            'alarms': alarms,
            'summary': alarm_summary,
            'total_alarms': len(alarms),
            'alarms_in_alarm': alarm_summary.get('ALARM', 0)
        }
    
    def get_ec2_health_status(self) -> Dict[str, Any]:
        """Get health status of all EC2 instances."""
        ec2 = self._get_client('ec2')
        if not ec2:
            return {'instances': [], 'error': 'EC2 client unavailable'}
        
        instances = []
        health_summary = {
            'healthy': 0,
            'impaired': 0,
            'initializing': 0,
            'unknown': 0
        }
        
        # Get all instances
        response = self._safe_api_call('ec2', ec2.describe_instances)
        if not response:
            return {'instances': instances, 'error': 'Could not describe instances'}
        
        instance_ids = []
        instance_map = {}
        
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_id = instance['InstanceId']
                state = instance.get('State', {}).get('Name', 'unknown')
                
                # Get instance name from tags
                instance_name = instance_id
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        instance_name = tag['Value']
                        break
                
                instance_map[instance_id] = {
                    'instance_id': instance_id,
                    'instance_name': instance_name,
                    'instance_type': instance.get('InstanceType', 'Unknown'),
                    'state': state,
                    'availability_zone': instance.get('Placement', {}).get('AvailabilityZone', 'Unknown'),
                    'private_ip': instance.get('PrivateIpAddress'),
                    'public_ip': instance.get('PublicIpAddress'),
                    'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None,
                    'system_status': 'unknown',
                    'instance_status': 'unknown',
                    'events': []
                }
                
                if state == 'running':
                    instance_ids.append(instance_id)
        
        # Get instance status checks for running instances
        if instance_ids:
            try:
                status_response = ec2.describe_instance_status(InstanceIds=instance_ids)
                for status in status_response.get('InstanceStatuses', []):
                    instance_id = status['InstanceId']
                    if instance_id in instance_map:
                        system_status = status.get('SystemStatus', {}).get('Status', 'unknown')
                        instance_status = status.get('InstanceStatus', {}).get('Status', 'unknown')
                        
                        instance_map[instance_id]['system_status'] = system_status
                        instance_map[instance_id]['instance_status'] = instance_status
                        
                        # Check for scheduled events
                        for event in status.get('Events', []):
                            instance_map[instance_id]['events'].append({
                                'code': event.get('Code'),
                                'description': event.get('Description'),
                                'not_before': event.get('NotBefore', '').isoformat() if event.get('NotBefore') else None,
                                'not_after': event.get('NotAfter', '').isoformat() if event.get('NotAfter') else None
                            })
                        
                        # Update health summary
                        if system_status == 'ok' and instance_status == 'ok':
                            health_summary['healthy'] += 1
                            instance_map[instance_id]['health'] = 'HEALTHY'
                        elif system_status == 'initializing' or instance_status == 'initializing':
                            health_summary['initializing'] += 1
                            instance_map[instance_id]['health'] = 'INITIALIZING'
                        elif system_status == 'impaired' or instance_status == 'impaired':
                            health_summary['impaired'] += 1
                            instance_map[instance_id]['health'] = 'IMPAIRED'
                        else:
                            health_summary['unknown'] += 1
                            instance_map[instance_id]['health'] = 'UNKNOWN'
            except ClientError as e:
                self.service_status['ec2_status'] = f"Error: {e}"
        
        instances = list(instance_map.values())
        
        # Sort by health status (impaired first)
        health_order = {'IMPAIRED': 0, 'UNKNOWN': 1, 'INITIALIZING': 2, 'HEALTHY': 3}
        instances.sort(key=lambda x: health_order.get(x.get('health', 'UNKNOWN'), 4))
        
        return {
            'instances': instances,
            'summary': health_summary,
            'total_instances': len(instances),
            'running_instances': len(instance_ids)
        }
    
    def get_rds_health_status(self) -> Dict[str, Any]:
        """Get health status of all RDS instances."""
        rds = self._get_client('rds')
        if not rds:
            return {'instances': [], 'error': 'RDS client unavailable'}
        
        instances = []
        health_summary = {
            'available': 0,
            'maintenance': 0,
            'issue': 0,
            'other': 0
        }
        
        response = self._safe_api_call('rds', rds.describe_db_instances)
        if not response:
            return {'instances': instances, 'error': 'Could not describe RDS instances'}
        
        for db in response.get('DBInstances', []):
            db_id = db['DBInstanceIdentifier']
            status = db.get('DBInstanceStatus', 'unknown')
            
            instance = {
                'db_identifier': db_id,
                'engine': db.get('Engine', 'Unknown'),
                'engine_version': db.get('EngineVersion', 'Unknown'),
                'instance_class': db.get('DBInstanceClass', 'Unknown'),
                'status': status,
                'multi_az': db.get('MultiAZ', False),
                'storage_type': db.get('StorageType', 'Unknown'),
                'allocated_storage_gb': db.get('AllocatedStorage', 0),
                'availability_zone': db.get('AvailabilityZone', 'Unknown'),
                'endpoint': db.get('Endpoint', {}).get('Address'),
                'port': db.get('Endpoint', {}).get('Port'),
                'maintenance_window': db.get('PreferredMaintenanceWindow'),
                'backup_window': db.get('PreferredBackupWindow'),
                'pending_modifications': db.get('PendingModifiedValues', {}),
                'events': []
            }
            
            # Determine health status
            if status == 'available':
                health_summary['available'] += 1
                instance['health'] = 'HEALTHY'
            elif status in ['maintenance', 'modifying', 'upgrading', 'configuring-enhanced-monitoring']:
                health_summary['maintenance'] += 1
                instance['health'] = 'MAINTENANCE'
            elif status in ['failed', 'incompatible-network', 'incompatible-option-group', 
                           'incompatible-parameters', 'incompatible-restore', 'storage-full']:
                health_summary['issue'] += 1
                instance['health'] = 'UNHEALTHY'
            else:
                health_summary['other'] += 1
                instance['health'] = 'UNKNOWN'
            
            instances.append(instance)
        
        # Get pending events
        try:
            events_response = rds.describe_events(
                Duration=1440,  # Last 24 hours
                SourceType='db-instance'
            )
            for event in events_response.get('Events', []):
                source_id = event.get('SourceIdentifier')
                for instance in instances:
                    if instance['db_identifier'] == source_id:
                        instance['events'].append({
                            'message': event.get('Message'),
                            'date': event.get('Date', '').isoformat() if event.get('Date') else None,
                            'categories': event.get('EventCategories', [])
                        })
        except ClientError:
            pass
        
        # Get pending maintenance
        try:
            maintenance_response = rds.describe_pending_maintenance_actions()
            for action in maintenance_response.get('PendingMaintenanceActions', []):
                resource_id = action.get('ResourceIdentifier', '').split(':')[-1]
                for instance in instances:
                    if instance['db_identifier'] == resource_id:
                        instance['pending_maintenance'] = [
                            {
                                'action': a.get('Action'),
                                'auto_apply_after': a.get('AutoAppliedAfterDate', '').isoformat() if a.get('AutoAppliedAfterDate') else None,
                                'forced_apply_date': a.get('ForcedApplyDate', '').isoformat() if a.get('ForcedApplyDate') else None,
                                'description': a.get('Description')
                            }
                            for a in action.get('PendingMaintenanceActionDetails', [])
                        ]
        except ClientError:
            pass
        
        # Sort by health status
        health_order = {'UNHEALTHY': 0, 'UNKNOWN': 1, 'MAINTENANCE': 2, 'HEALTHY': 3}
        instances.sort(key=lambda x: health_order.get(x.get('health', 'UNKNOWN'), 4))
        
        return {
            'instances': instances,
            'summary': health_summary,
            'total_instances': len(instances)
        }
    
    def get_lambda_health_status(self, hours: int = 24) -> Dict[str, Any]:
        """Get health status of Lambda functions based on error rates."""
        lambda_client = self._get_client('lambda')
        cw = self._get_client('cloudwatch')
        
        if not lambda_client or not cw:
            return {'functions': [], 'error': 'Lambda or CloudWatch client unavailable'}
        
        functions = []
        health_summary = {
            'healthy': 0,
            'degraded': 0,
            'unhealthy': 0,
            'inactive': 0
        }
        
        response = self._safe_api_call('lambda', lambda_client.list_functions)
        if not response:
            return {'functions': functions, 'error': 'Could not list Lambda functions'}
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        for func in response.get('Functions', []):
            func_name = func['FunctionName']
            
            function_info = {
                'function_name': func_name,
                'runtime': func.get('Runtime', 'Unknown'),
                'memory_mb': func.get('MemorySize', 128),
                'timeout_sec': func.get('Timeout', 3),
                'last_modified': func.get('LastModified'),
                'invocations': 0,
                'errors': 0,
                'error_rate': 0,
                'avg_duration_ms': 0,
                'throttles': 0
            }
            
            # Get metrics
            try:
                # Invocations
                invocations = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600 * hours,  # Single period for total
                    Statistics=['Sum']
                )
                if invocations.get('Datapoints'):
                    function_info['invocations'] = int(sum(dp['Sum'] for dp in invocations['Datapoints']))
                
                # Errors
                errors = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Errors',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600 * hours,
                    Statistics=['Sum']
                )
                if errors.get('Datapoints'):
                    function_info['errors'] = int(sum(dp['Sum'] for dp in errors['Datapoints']))
                
                # Duration
                duration = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Duration',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600 * hours,
                    Statistics=['Average']
                )
                if duration.get('Datapoints'):
                    function_info['avg_duration_ms'] = round(
                        sum(dp['Average'] for dp in duration['Datapoints']) / len(duration['Datapoints']), 2
                    )
                
                # Throttles
                throttles = cw.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Throttles',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=3600 * hours,
                    Statistics=['Sum']
                )
                if throttles.get('Datapoints'):
                    function_info['throttles'] = int(sum(dp['Sum'] for dp in throttles['Datapoints']))
                
            except ClientError:
                pass
            
            # Calculate error rate and health
            if function_info['invocations'] > 0:
                function_info['error_rate'] = round(
                    (function_info['errors'] / function_info['invocations']) * 100, 2
                )
                
                if function_info['error_rate'] >= 10 or function_info['throttles'] > 10:
                    health_summary['unhealthy'] += 1
                    function_info['health'] = 'UNHEALTHY'
                elif function_info['error_rate'] >= 1 or function_info['throttles'] > 0:
                    health_summary['degraded'] += 1
                    function_info['health'] = 'DEGRADED'
                else:
                    health_summary['healthy'] += 1
                    function_info['health'] = 'HEALTHY'
            else:
                health_summary['inactive'] += 1
                function_info['health'] = 'INACTIVE'
            
            functions.append(function_info)
        
        # Sort by health status
        health_order = {'UNHEALTHY': 0, 'DEGRADED': 1, 'HEALTHY': 2, 'INACTIVE': 3}
        functions.sort(key=lambda x: (health_order.get(x.get('health', 'INACTIVE'), 4), -x['invocations']))
        
        return {
            'functions': functions,
            'summary': health_summary,
            'total_functions': len(functions),
            'analysis_period_hours': hours
        }
    
    def get_ecs_health_status(self) -> Dict[str, Any]:
        """Get health status of ECS clusters and services."""
        ecs = self._get_client('ecs')
        if not ecs:
            return {'clusters': [], 'error': 'ECS client unavailable'}
        
        clusters = []
        
        # List clusters
        clusters_response = self._safe_api_call('ecs', ecs.list_clusters)
        if not clusters_response:
            return {'clusters': clusters, 'error': 'Could not list ECS clusters'}
        
        cluster_arns = clusters_response.get('clusterArns', [])
        if not cluster_arns:
            return {'clusters': clusters, 'message': 'No ECS clusters found'}
        
        # Describe clusters
        try:
            describe_response = ecs.describe_clusters(
                clusters=cluster_arns,
                include=['ATTACHMENTS', 'SETTINGS', 'STATISTICS']
            )
            
            for cluster in describe_response.get('clusters', []):
                cluster_name = cluster['clusterName']
                
                cluster_info = {
                    'cluster_name': cluster_name,
                    'status': cluster.get('status', 'unknown'),
                    'running_tasks': cluster.get('runningTasksCount', 0),
                    'pending_tasks': cluster.get('pendingTasksCount', 0),
                    'active_services': cluster.get('activeServicesCount', 0),
                    'registered_instances': cluster.get('registeredContainerInstancesCount', 0),
                    'services': []
                }
                
                # Get services for this cluster
                try:
                    services_response = ecs.list_services(cluster=cluster_name)
                    service_arns = services_response.get('serviceArns', [])
                    
                    if service_arns:
                        services_detail = ecs.describe_services(
                            cluster=cluster_name,
                            services=service_arns[:10]  # Limit to first 10
                        )
                        
                        for service in services_detail.get('services', []):
                            service_info = {
                                'service_name': service['serviceName'],
                                'status': service.get('status', 'unknown'),
                                'desired_count': service.get('desiredCount', 0),
                                'running_count': service.get('runningCount', 0),
                                'pending_count': service.get('pendingCount', 0),
                                'deployment_status': 'STABLE' if service.get('runningCount') == service.get('desiredCount') else 'DEPLOYING'
                            }
                            
                            # Determine health
                            if service_info['running_count'] == service_info['desired_count'] and service_info['desired_count'] > 0:
                                service_info['health'] = 'HEALTHY'
                            elif service_info['running_count'] > 0:
                                service_info['health'] = 'DEGRADED'
                            else:
                                service_info['health'] = 'UNHEALTHY'
                            
                            cluster_info['services'].append(service_info)
                except ClientError:
                    pass
                
                # Determine cluster health
                healthy_services = len([s for s in cluster_info['services'] if s['health'] == 'HEALTHY'])
                if healthy_services == len(cluster_info['services']) and cluster_info['services']:
                    cluster_info['health'] = 'HEALTHY'
                elif healthy_services > 0:
                    cluster_info['health'] = 'DEGRADED'
                else:
                    cluster_info['health'] = 'UNHEALTHY' if cluster_info['services'] else 'UNKNOWN'
                
                clusters.append(cluster_info)
        except ClientError as e:
            self.service_status['ecs'] = f"Error: {e}"
        
        return {
            'clusters': clusters,
            'total_clusters': len(clusters)
        }
    
    def get_service_availability(self) -> Dict[str, Any]:
        """Check AWS service availability using AWS Health API."""
        services = {
            'ec2': {'status': 'unknown', 'message': ''},
            'rds': {'status': 'unknown', 'message': ''},
            'lambda': {'status': 'unknown', 'message': ''},
            's3': {'status': 'unknown', 'message': ''},
            'dynamodb': {'status': 'unknown', 'message': ''},
            'cloudwatch': {'status': 'unknown', 'message': ''}
        }
        
        # AWS Health API is ONLY available in us-east-1 region
        # Requires Business or Enterprise support plan
        # Skip for now to avoid endpoint errors
        health = None
        
        # Note: Uncomment below to enable AWS Health API (requires Business/Enterprise support)
        # try:
        #     health = boto3.client('health', region_name='us-east-1')
        # except Exception as e:
        #     self.service_status['health'] = f"Health API unavailable: {str(e)[:50]}"
        #     health = None
        
        # Try AWS Health API first (if enabled)
        if health:
            try:
                events = health.describe_events(
                    filter={
                        'eventStatusCodes': ['open', 'upcoming'],
                        'eventTypeCategories': ['issue', 'scheduledChange']
                    }
                )
                
                for event in events.get('events', []):
                    service = event.get('service', '').lower()
                    if service in services:
                        services[service] = {
                            'status': 'issue' if event['eventTypeCategory'] == 'issue' else 'scheduled',
                            'message': event.get('eventTypeCode', ''),
                            'region': event.get('region', 'global')
                        }
                
                # Mark services without issues as available
                for service in services:
                    if services[service]['status'] == 'unknown':
                        services[service] = {'status': 'available', 'message': 'No issues reported'}
                
                return {
                    'services': services,
                    'source': 'aws_health_api',
                    'last_checked': datetime.now().isoformat()
                }
            except ClientError as e:
                if 'SubscriptionRequiredException' in str(e):
                    self.service_status['health'] = "Requires Business/Enterprise support plan"
        
        # Fall back to basic connectivity checks
        for service_name in services.keys():
            try:
                client = self._get_client(service_name)
                if client:
                    # Simple API call to verify connectivity
                    if service_name == 'ec2':
                        client.describe_regions(DryRun=False)
                    elif service_name == 'rds':
                        client.describe_db_instances(MaxRecords=20)
                    elif service_name == 'lambda':
                        client.list_functions(MaxItems=1)
                    elif service_name == 's3':
                        client.list_buckets()
                    elif service_name == 'dynamodb':
                        client.list_tables(Limit=1)
                    elif service_name == 'cloudwatch':
                        client.list_metrics(Limit=1)
                    
                    services[service_name] = {'status': 'available', 'message': 'Service accessible'}
            except Exception as e:
                services[service_name] = {'status': 'error', 'message': str(e)[:100]}
        
        return {
            'services': services,
            'source': 'connectivity_check',
            'last_checked': datetime.now().isoformat()
        }
    
    def calculate_health_scores(self) -> Dict[str, Any]:
        """Calculate health scores for each service category."""
        scores = {}
        
        # EC2 Health Score
        ec2_health = self.get_ec2_health_status()
        ec2_summary = ec2_health.get('summary', {})
        total_ec2 = sum(ec2_summary.values())
        if total_ec2 > 0:
            ec2_score = (ec2_summary.get('healthy', 0) / total_ec2) * 100
            scores['ec2'] = {
                'score': round(ec2_score),
                'healthy': ec2_summary.get('healthy', 0),
                'impaired': ec2_summary.get('impaired', 0),
                'total': total_ec2
            }
        else:
            scores['ec2'] = {'score': 100, 'message': 'No EC2 instances'}
        
        # RDS Health Score
        rds_health = self.get_rds_health_status()
        rds_summary = rds_health.get('summary', {})
        total_rds = sum(rds_summary.values())
        if total_rds > 0:
            rds_score = (rds_summary.get('available', 0) / total_rds) * 100
            scores['rds'] = {
                'score': round(rds_score),
                'available': rds_summary.get('available', 0),
                'issues': rds_summary.get('issue', 0),
                'total': total_rds
            }
        else:
            scores['rds'] = {'score': 100, 'message': 'No RDS instances'}
        
        # Lambda Health Score
        lambda_health = self.get_lambda_health_status()
        lambda_summary = lambda_health.get('summary', {})
        total_lambda = lambda_summary.get('healthy', 0) + lambda_summary.get('degraded', 0) + lambda_summary.get('unhealthy', 0)
        if total_lambda > 0:
            lambda_score = (lambda_summary.get('healthy', 0) / total_lambda) * 100
            scores['lambda'] = {
                'score': round(lambda_score),
                'healthy': lambda_summary.get('healthy', 0),
                'degraded': lambda_summary.get('degraded', 0),
                'unhealthy': lambda_summary.get('unhealthy', 0),
                'total': total_lambda
            }
        else:
            scores['lambda'] = {'score': 100, 'message': 'No active Lambda functions'}
        
        # CloudWatch Alarms Health Score
        alarms_health = self.get_cloudwatch_alarms_status()
        alarms_summary = alarms_health.get('summary', {})
        total_alarms = sum(alarms_summary.values())
        if total_alarms > 0:
            alarms_score = (alarms_summary.get('OK', 0) / total_alarms) * 100
            scores['cloudwatch_alarms'] = {
                'score': round(alarms_score),
                'ok': alarms_summary.get('OK', 0),
                'alarm': alarms_summary.get('ALARM', 0),
                'insufficient_data': alarms_summary.get('INSUFFICIENT_DATA', 0),
                'total': total_alarms
            }
        else:
            scores['cloudwatch_alarms'] = {'score': 100, 'message': 'No CloudWatch alarms configured'}
        
        # Calculate overall health score (weighted average)
        weights = {'ec2': 0.3, 'rds': 0.3, 'lambda': 0.25, 'cloudwatch_alarms': 0.15}
        overall_score = 0
        total_weight = 0
        
        for service, weight in weights.items():
            if 'score' in scores.get(service, {}):
                overall_score += scores[service]['score'] * weight
                total_weight += weight
        
        scores['overall'] = {
            'score': round(overall_score / total_weight) if total_weight > 0 else 100,
            'status': self._get_health_status_label(overall_score / total_weight if total_weight > 0 else 100)
        }
        
        return scores
    
    def _get_health_status_label(self, score: float) -> str:
        """Convert health score to status label."""
        if score >= 90:
            return 'EXCELLENT'
        elif score >= 70:
            return 'GOOD'
        elif score >= 50:
            return 'FAIR'
        elif score >= 30:
            return 'POOR'
        else:
            return 'CRITICAL'
    
    def run_full_health_check(self) -> Dict[str, Any]:
        """Run comprehensive health check across all services."""
        self.service_status = {}  # Reset status
        
        results = {
            'check_time': datetime.now().isoformat(),
            'cloudwatch_alarms': self.get_cloudwatch_alarms_status(),
            'ec2': self.get_ec2_health_status(),
            'rds': self.get_rds_health_status(),
            'lambda': self.get_lambda_health_status(),
            'ecs': self.get_ecs_health_status(),
            'service_availability': self.get_service_availability(),
            'health_scores': self.calculate_health_scores(),
            'service_status': self.service_status
        }
        
        return results
    
    def get_ai_recommendations(self, health_results: Dict[str, Any]) -> Optional[str]:
        """Get AI-powered health recommendations."""
        if not self.openai_client:
            return None
        
        # Prepare summary for AI
        summary = {
            'health_scores': health_results.get('health_scores', {}),
            'alarms_in_alarm': health_results.get('cloudwatch_alarms', {}).get('alarms_in_alarm', 0),
            'ec2_impaired': health_results.get('ec2', {}).get('summary', {}).get('impaired', 0),
            'rds_issues': health_results.get('rds', {}).get('summary', {}).get('issue', 0),
            'lambda_unhealthy': health_results.get('lambda', {}).get('summary', {}).get('unhealthy', 0)
        }
        
        system_prompt = """You are an AWS infrastructure health expert. Analyze the health check results and provide:

1. **Health Summary**: Overall infrastructure health assessment
2. **Critical Issues**: Immediate problems requiring attention
3. **Proactive Recommendations**: Steps to prevent future issues
4. **Monitoring Improvements**: Suggestions for better observability
5. **Recovery Actions**: Steps for any failing resources

Format your response in clear Markdown with headers and bullet points.
Be concise and actionable."""

        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze this AWS health check data:\n\n{json.dumps(summary, indent=2)}"}
                ],
                max_tokens=1500,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating AI recommendations: {str(e)}"
