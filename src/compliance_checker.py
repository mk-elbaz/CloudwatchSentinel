"""
AWS Compliance Checker with AI-powered recommendations.
Checks against AWS Well-Architected Framework, tagging compliance, backup policies, and Multi-AZ deployments.
"""

import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from openai import OpenAI
import os
import json
from botocore.exceptions import ClientError, NoCredentialsError


class AWSComplianceChecker:
    """Checks AWS resources against best practices and compliance standards."""
    
    # Well-Architected Framework pillars
    PILLARS = {
        'operational_excellence': 'Operational Excellence',
        'security': 'Security',
        'reliability': 'Reliability',
        'performance_efficiency': 'Performance Efficiency',
        'cost_optimization': 'Cost Optimization',
        'sustainability': 'Sustainability'
    }
    
    # Required tags for compliance
    DEFAULT_REQUIRED_TAGS = ['Environment', 'Owner', 'Project', 'CostCenter']
    
    def __init__(self):
        """Initialize boto3 clients and OpenAI client."""
        self.region = os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        self.required_tags = os.getenv('REQUIRED_TAGS', ','.join(self.DEFAULT_REQUIRED_TAGS)).split(',')
        
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
    
    def check_tagging_compliance(self) -> Dict[str, Any]:
        """Audit resources for tagging compliance."""
        findings = []
        compliant_count = 0
        non_compliant_count = 0
        
        tagging = self._get_client('resourcegroupstaggingapi')
        if not tagging:
            return {'findings': findings, 'error': 'Resource Groups Tagging API unavailable'}
        
        # Get all tagged resources
        paginator = tagging.get_paginator('get_resources')
        resources = []
        
        try:
            for page in paginator.paginate():
                resources.extend(page.get('ResourceTagMappingList', []))
        except ClientError as e:
            self.service_status['tagging'] = f"Error: {e}"
            return {'findings': findings, 'error': str(e)}
        
        # Check each resource for required tags
        for resource in resources:
            arn = resource.get('ResourceARN', '')
            tags = {t['Key']: t['Value'] for t in resource.get('Tags', [])}
            
            missing_tags = [tag for tag in self.required_tags if tag not in tags]
            
            if missing_tags:
                non_compliant_count += 1
                
                # Extract resource type and ID from ARN
                arn_parts = arn.split(':')
                service = arn_parts[2] if len(arn_parts) > 2 else 'unknown'
                resource_id = arn.split('/')[-1] if '/' in arn else arn.split(':')[-1]
                
                findings.append({
                    'type': 'MISSING_REQUIRED_TAGS',
                    'severity': 'MEDIUM',
                    'resource_type': service.upper(),
                    'resource_id': resource_id,
                    'resource_arn': arn,
                    'title': f'Resource missing required tags',
                    'description': f'Resource is missing tags: {", ".join(missing_tags)}',
                    'missing_tags': missing_tags,
                    'existing_tags': list(tags.keys()),
                    'recommendation': f'Add missing tags: {", ".join(missing_tags)}'
                })
            else:
                compliant_count += 1
        
        # Check for resources without any tags
        ec2 = self._get_client('ec2')
        if ec2:
            try:
                # Check EC2 instances
                instances = ec2.describe_instances()
                for reservation in instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        if not instance.get('Tags'):
                            non_compliant_count += 1
                            findings.append({
                                'type': 'NO_TAGS',
                                'severity': 'HIGH',
                                'resource_type': 'EC2',
                                'resource_id': instance['InstanceId'],
                                'title': 'EC2 instance has no tags',
                                'description': f'Instance {instance["InstanceId"]} has no tags configured',
                                'recommendation': 'Add required tags for resource management and cost allocation'
                            })
                
                # Check EBS volumes
                volumes = ec2.describe_volumes()
                for volume in volumes.get('Volumes', []):
                    if not volume.get('Tags'):
                        non_compliant_count += 1
                        findings.append({
                            'type': 'NO_TAGS',
                            'severity': 'LOW',
                            'resource_type': 'EBS',
                            'resource_id': volume['VolumeId'],
                            'title': 'EBS volume has no tags',
                            'description': f'Volume {volume["VolumeId"]} has no tags configured',
                            'recommendation': 'Add tags for resource management and cost allocation'
                        })
            except ClientError:
                pass
        
        return {
            'findings': findings,
            'summary': {
                'compliant': compliant_count,
                'non_compliant': non_compliant_count,
                'compliance_rate': round(compliant_count / max(compliant_count + non_compliant_count, 1) * 100, 1)
            },
            'required_tags': self.required_tags
        }
    
    def check_backup_policies(self) -> Dict[str, Any]:
        """Verify backup policies are configured."""
        findings = []
        
        backup = self._get_client('backup')
        rds = self._get_client('rds')
        
        # Check AWS Backup plans
        if backup:
            try:
                plans = backup.list_backup_plans()
                if not plans.get('BackupPlansList'):
                    findings.append({
                        'type': 'NO_BACKUP_PLANS',
                        'severity': 'HIGH',
                        'resource_type': 'AWSBackup',
                        'resource_id': 'account',
                        'title': 'No AWS Backup plans configured',
                        'description': 'No centralized backup plans found in AWS Backup',
                        'recommendation': 'Create AWS Backup plans for critical resources'
                    })
                else:
                    for plan in plans.get('BackupPlansList', []):
                        plan_id = plan['BackupPlanId']
                        plan_name = plan['BackupPlanName']
                        
                        # Check backup selections for this plan
                        selections = backup.list_backup_selections(BackupPlanId=plan_id)
                        if not selections.get('BackupSelectionsList'):
                            findings.append({
                                'type': 'EMPTY_BACKUP_PLAN',
                                'severity': 'MEDIUM',
                                'resource_type': 'BackupPlan',
                                'resource_id': plan_id,
                                'resource_name': plan_name,
                                'title': f'Backup plan has no resource selections',
                                'description': f'Backup plan "{plan_name}" has no resources assigned',
                                'recommendation': 'Add resource selections to the backup plan'
                            })
            except ClientError as e:
                self.service_status['backup'] = f"Error: {e}"
        
        # Check RDS automated backups
        if rds:
            try:
                instances = rds.describe_db_instances()
                for instance in instances.get('DBInstances', []):
                    db_id = instance['DBInstanceIdentifier']
                    retention = instance.get('BackupRetentionPeriod', 0)
                    
                    if retention == 0:
                        findings.append({
                            'type': 'RDS_NO_BACKUP',
                            'severity': 'CRITICAL',
                            'resource_type': 'RDS',
                            'resource_id': db_id,
                            'title': 'RDS instance has no automated backups',
                            'description': f'Database {db_id} has backup retention set to 0',
                            'recommendation': 'Enable automated backups with appropriate retention period'
                        })
                    elif retention < 7:
                        findings.append({
                            'type': 'RDS_LOW_RETENTION',
                            'severity': 'MEDIUM',
                            'resource_type': 'RDS',
                            'resource_id': db_id,
                            'title': f'RDS backup retention is only {retention} days',
                            'description': f'Database {db_id} has short backup retention period',
                            'recommendation': 'Consider increasing backup retention to at least 7 days'
                        })
            except ClientError:
                pass
        
        # Check EC2 instances without backups
        ec2 = self._get_client('ec2')
        if ec2 and backup:
            try:
                instances = ec2.describe_instances(
                    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
                )
                
                # Get protected resources
                protected_resources = set()
                try:
                    paginator = backup.get_paginator('list_protected_resources')
                    for page in paginator.paginate():
                        for resource in page.get('Results', []):
                            protected_resources.add(resource.get('ResourceArn', ''))
                except ClientError:
                    pass
                
                for reservation in instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_id = instance['InstanceId']
                        instance_arn = f"arn:aws:ec2:{self.region}:{instance.get('OwnerId', '')}:instance/{instance_id}"
                        
                        # Check if instance name suggests it's important
                        instance_name = ''
                        for tag in instance.get('Tags', []):
                            if tag['Key'] == 'Name':
                                instance_name = tag['Value']
                                break
                        
                        important_keywords = ['prod', 'production', 'database', 'db', 'critical', 'master']
                        is_important = any(kw in instance_name.lower() for kw in important_keywords)
                        
                        if instance_arn not in protected_resources and is_important:
                            findings.append({
                                'type': 'EC2_NO_BACKUP',
                                'severity': 'HIGH',
                                'resource_type': 'EC2',
                                'resource_id': instance_id,
                                'resource_name': instance_name,
                                'title': 'Important EC2 instance not in backup plan',
                                'description': f'Instance "{instance_name}" appears important but is not protected by AWS Backup',
                                'recommendation': 'Add this instance to an AWS Backup plan'
                            })
            except ClientError:
                pass
        
        return {
            'findings': findings,
            'total_findings': len(findings)
        }
    
    def check_multi_az_deployments(self) -> Dict[str, Any]:
        """Check for Multi-AZ deployment compliance."""
        findings = []
        
        rds = self._get_client('rds')
        elb = self._get_client('elbv2')
        ec2 = self._get_client('ec2')
        
        # Check RDS Multi-AZ
        if rds:
            try:
                instances = rds.describe_db_instances()
                for instance in instances.get('DBInstances', []):
                    db_id = instance['DBInstanceIdentifier']
                    engine = instance.get('Engine', '')
                    multi_az = instance.get('MultiAZ', False)
                    
                    # Skip Aurora (uses different HA model)
                    if 'aurora' in engine:
                        continue
                    
                    if not multi_az:
                        # Check if this looks like a production database
                        is_prod = any(kw in db_id.lower() for kw in ['prod', 'production', 'live', 'main'])
                        
                        findings.append({
                            'type': 'RDS_SINGLE_AZ',
                            'severity': 'HIGH' if is_prod else 'MEDIUM',
                            'resource_type': 'RDS',
                            'resource_id': db_id,
                            'pillar': 'reliability',
                            'title': 'RDS instance is not Multi-AZ',
                            'description': f'Database {db_id} is deployed in a single Availability Zone',
                            'recommendation': 'Enable Multi-AZ for high availability and automatic failover'
                        })
            except ClientError:
                pass
        
        # Check ELB cross-zone load balancing and AZ distribution
        if elb:
            try:
                load_balancers = elb.describe_load_balancers()
                for lb in load_balancers.get('LoadBalancers', []):
                    lb_arn = lb['LoadBalancerArn']
                    lb_name = lb['LoadBalancerName']
                    azs = lb.get('AvailabilityZones', [])
                    
                    if len(azs) < 2:
                        findings.append({
                            'type': 'ELB_SINGLE_AZ',
                            'severity': 'HIGH',
                            'resource_type': 'ELB',
                            'resource_id': lb_name,
                            'pillar': 'reliability',
                            'title': 'Load balancer spans only one AZ',
                            'description': f'Load balancer {lb_name} is deployed in only {len(azs)} Availability Zone(s)',
                            'recommendation': 'Add subnets from at least 2 Availability Zones'
                        })
            except ClientError:
                pass
        
        # Check Auto Scaling Groups for AZ distribution
        asg = self._get_client('autoscaling')
        if asg:
            try:
                groups = asg.describe_auto_scaling_groups()
                for group in groups.get('AutoScalingGroups', []):
                    group_name = group['AutoScalingGroupName']
                    azs = group.get('AvailabilityZones', [])
                    
                    if len(azs) < 2:
                        findings.append({
                            'type': 'ASG_SINGLE_AZ',
                            'severity': 'MEDIUM',
                            'resource_type': 'AutoScalingGroup',
                            'resource_id': group_name,
                            'pillar': 'reliability',
                            'title': 'Auto Scaling Group uses single AZ',
                            'description': f'ASG {group_name} is configured for only {len(azs)} AZ(s)',
                            'recommendation': 'Configure ASG to span at least 2 Availability Zones'
                        })
            except ClientError:
                pass
        
        # Check ElastiCache clusters
        elasticache = self._get_client('elasticache')
        if elasticache:
            try:
                clusters = elasticache.describe_cache_clusters()
                for cluster in clusters.get('CacheClusters', []):
                    cluster_id = cluster['CacheClusterId']
                    num_nodes = cluster.get('NumCacheNodes', 1)
                    
                    if num_nodes < 2:
                        findings.append({
                            'type': 'ELASTICACHE_SINGLE_NODE',
                            'severity': 'MEDIUM',
                            'resource_type': 'ElastiCache',
                            'resource_id': cluster_id,
                            'pillar': 'reliability',
                            'title': 'ElastiCache cluster has single node',
                            'description': f'Cache cluster {cluster_id} has only {num_nodes} node(s)',
                            'recommendation': 'Add more nodes and enable Multi-AZ for high availability'
                        })
            except ClientError:
                pass
        
        return {
            'findings': findings,
            'total_findings': len(findings)
        }
    
    def check_well_architected_practices(self) -> Dict[str, Any]:
        """Run Well-Architected Framework best practices checks."""
        findings = []
        pillar_scores = {pillar: 100 for pillar in self.PILLARS.keys()}
        
        # SECURITY PILLAR
        # Check for encrypted EBS volumes
        ec2 = self._get_client('ec2')
        if ec2:
            try:
                volumes = ec2.describe_volumes()
                for volume in volumes.get('Volumes', []):
                    if not volume.get('Encrypted', False):
                        findings.append({
                            'type': 'EBS_NOT_ENCRYPTED',
                            'severity': 'HIGH',
                            'resource_type': 'EBS',
                            'resource_id': volume['VolumeId'],
                            'pillar': 'security',
                            'title': 'EBS volume is not encrypted',
                            'description': f'Volume {volume["VolumeId"]} is not encrypted at rest',
                            'recommendation': 'Enable encryption for EBS volumes to protect data at rest'
                        })
                        pillar_scores['security'] -= 5
            except ClientError:
                pass
            
            # Check for default VPC usage
            try:
                vpcs = ec2.describe_vpcs()
                for vpc in vpcs.get('Vpcs', []):
                    if vpc.get('IsDefault', False):
                        # Check if default VPC has resources
                        instances = ec2.describe_instances(
                            Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]
                        )
                        if instances.get('Reservations'):
                            findings.append({
                                'type': 'DEFAULT_VPC_IN_USE',
                                'severity': 'MEDIUM',
                                'resource_type': 'VPC',
                                'resource_id': vpc['VpcId'],
                                'pillar': 'security',
                                'title': 'Resources running in default VPC',
                                'description': 'Default VPC is being used for production workloads',
                                'recommendation': 'Use custom VPCs with proper network segmentation'
                            })
                            pillar_scores['security'] -= 10
            except ClientError:
                pass
        
        # RELIABILITY PILLAR
        # Check CloudWatch alarms exist for critical metrics
        cw = self._get_client('cloudwatch')
        if cw:
            try:
                alarms = cw.describe_alarms()
                if not alarms.get('MetricAlarms'):
                    findings.append({
                        'type': 'NO_CLOUDWATCH_ALARMS',
                        'severity': 'HIGH',
                        'resource_type': 'CloudWatch',
                        'resource_id': 'account',
                        'pillar': 'reliability',
                        'title': 'No CloudWatch alarms configured',
                        'description': 'No metric alarms found for monitoring infrastructure health',
                        'recommendation': 'Create CloudWatch alarms for critical metrics (CPU, memory, errors)'
                    })
                    pillar_scores['reliability'] -= 20
            except ClientError:
                pass
        
        # PERFORMANCE EFFICIENCY PILLAR
        # Check for outdated instance types
        if ec2:
            try:
                instances = ec2.describe_instances(
                    Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
                )
                old_generations = ['t2.', 'm4.', 'c4.', 'r4.', 'i2.', 'd2.']
                
                for reservation in instances.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_type = instance.get('InstanceType', '')
                        if any(instance_type.startswith(gen) for gen in old_generations):
                            instance_name = ''
                            for tag in instance.get('Tags', []):
                                if tag['Key'] == 'Name':
                                    instance_name = tag['Value']
                                    break
                            
                            findings.append({
                                'type': 'OLD_INSTANCE_GENERATION',
                                'severity': 'LOW',
                                'resource_type': 'EC2',
                                'resource_id': instance['InstanceId'],
                                'resource_name': instance_name,
                                'pillar': 'performance_efficiency',
                                'title': f'Instance using older generation type ({instance_type})',
                                'description': 'Older instance generations may have lower price-performance ratio',
                                'recommendation': 'Consider upgrading to newer instance generation for better performance per dollar'
                            })
                            pillar_scores['performance_efficiency'] -= 2
            except ClientError:
                pass
        
        # COST OPTIMIZATION PILLAR
        # Check for unattached EBS volumes
        if ec2:
            try:
                volumes = ec2.describe_volumes(
                    Filters=[{'Name': 'status', 'Values': ['available']}]
                )
                for volume in volumes.get('Volumes', []):
                    size_gb = volume.get('Size', 0)
                    findings.append({
                        'type': 'UNATTACHED_EBS_VOLUME',
                        'severity': 'LOW',
                        'resource_type': 'EBS',
                        'resource_id': volume['VolumeId'],
                        'pillar': 'cost_optimization',
                        'title': f'Unattached EBS volume ({size_gb} GB)',
                        'description': f'Volume {volume["VolumeId"]} is not attached to any instance',
                        'recommendation': 'Delete unused volumes or snapshot and delete to save costs'
                    })
                    pillar_scores['cost_optimization'] -= 2
            except ClientError:
                pass
            
            # Check for unassociated Elastic IPs
            try:
                addresses = ec2.describe_addresses()
                for addr in addresses.get('Addresses', []):
                    if not addr.get('AssociationId'):
                        findings.append({
                            'type': 'UNASSOCIATED_EIP',
                            'severity': 'LOW',
                            'resource_type': 'ElasticIP',
                            'resource_id': addr.get('AllocationId', addr.get('PublicIp')),
                            'pillar': 'cost_optimization',
                            'title': 'Unassociated Elastic IP',
                            'description': f'Elastic IP {addr.get("PublicIp")} is not associated with any resource',
                            'recommendation': 'Release unused Elastic IPs to avoid charges'
                        })
                        pillar_scores['cost_optimization'] -= 3
            except ClientError:
                pass
        
        # OPERATIONAL EXCELLENCE PILLAR
        # Check for CloudTrail
        cloudtrail = self._get_client('cloudtrail')
        if cloudtrail:
            try:
                trails = cloudtrail.describe_trails()
                if not trails.get('trailList'):
                    findings.append({
                        'type': 'NO_CLOUDTRAIL',
                        'severity': 'HIGH',
                        'resource_type': 'CloudTrail',
                        'resource_id': 'account',
                        'pillar': 'operational_excellence',
                        'title': 'CloudTrail is not enabled',
                        'description': 'No CloudTrail trails found for API logging and auditing',
                        'recommendation': 'Enable CloudTrail for governance, compliance, and operational auditing'
                    })
                    pillar_scores['operational_excellence'] -= 25
                else:
                    # Check if any trail is logging
                    active_trails = 0
                    for trail in trails.get('trailList', []):
                        try:
                            status = cloudtrail.get_trail_status(Name=trail['Name'])
                            if status.get('IsLogging'):
                                active_trails += 1
                        except ClientError:
                            pass
                    
                    if active_trails == 0:
                        findings.append({
                            'type': 'CLOUDTRAIL_NOT_LOGGING',
                            'severity': 'HIGH',
                            'resource_type': 'CloudTrail',
                            'resource_id': 'account',
                            'pillar': 'operational_excellence',
                            'title': 'CloudTrail logging is disabled',
                            'description': 'No active CloudTrail trails are currently logging',
                            'recommendation': 'Enable logging on at least one CloudTrail trail'
                        })
                        pillar_scores['operational_excellence'] -= 20
            except ClientError:
                pass
        
        # Cap scores at 0
        for pillar in pillar_scores:
            pillar_scores[pillar] = max(0, pillar_scores[pillar])
        
        # Calculate overall compliance score
        overall_score = sum(pillar_scores.values()) / len(pillar_scores)
        
        return {
            'findings': findings,
            'pillar_scores': pillar_scores,
            'overall_score': round(overall_score),
            'total_findings': len(findings)
        }
    
    def check_logging_and_monitoring(self) -> Dict[str, Any]:
        """Check logging and monitoring compliance."""
        findings = []
        
        # Check VPC Flow Logs
        ec2 = self._get_client('ec2')
        if ec2:
            try:
                vpcs = ec2.describe_vpcs()
                flow_logs = ec2.describe_flow_logs()
                
                vpc_with_flow_logs = set()
                for fl in flow_logs.get('FlowLogs', []):
                    vpc_with_flow_logs.add(fl.get('ResourceId', ''))
                
                for vpc in vpcs.get('Vpcs', []):
                    vpc_id = vpc['VpcId']
                    if vpc_id not in vpc_with_flow_logs:
                        findings.append({
                            'type': 'NO_VPC_FLOW_LOGS',
                            'severity': 'MEDIUM',
                            'resource_type': 'VPC',
                            'resource_id': vpc_id,
                            'title': 'VPC does not have Flow Logs enabled',
                            'description': f'VPC {vpc_id} has no flow logs for network traffic analysis',
                            'recommendation': 'Enable VPC Flow Logs for network monitoring and security analysis'
                        })
            except ClientError:
                pass
        
        # Check S3 access logging
        s3 = self._get_client('s3')
        if s3:
            try:
                buckets = s3.list_buckets()
                for bucket in buckets.get('Buckets', []):
                    bucket_name = bucket['Name']
                    try:
                        logging = s3.get_bucket_logging(Bucket=bucket_name)
                        if not logging.get('LoggingEnabled'):
                            findings.append({
                                'type': 'S3_NO_ACCESS_LOGGING',
                                'severity': 'LOW',
                                'resource_type': 'S3',
                                'resource_id': bucket_name,
                                'title': 'S3 bucket access logging not enabled',
                                'description': f'Bucket {bucket_name} does not have access logging enabled',
                                'recommendation': 'Enable access logging for audit and security purposes'
                            })
                    except ClientError:
                        pass
            except ClientError:
                pass
        
        # Check ELB access logging
        elb = self._get_client('elbv2')
        if elb:
            try:
                load_balancers = elb.describe_load_balancers()
                for lb in load_balancers.get('LoadBalancers', []):
                    lb_arn = lb['LoadBalancerArn']
                    lb_name = lb['LoadBalancerName']
                    
                    attrs = elb.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                    access_logs_enabled = False
                    for attr in attrs.get('Attributes', []):
                        if attr['Key'] == 'access_logs.s3.enabled' and attr['Value'] == 'true':
                            access_logs_enabled = True
                            break
                    
                    if not access_logs_enabled:
                        findings.append({
                            'type': 'ELB_NO_ACCESS_LOGS',
                            'severity': 'MEDIUM',
                            'resource_type': 'ELB',
                            'resource_id': lb_name,
                            'title': 'Load balancer access logs not enabled',
                            'description': f'ELB {lb_name} does not have access logging enabled',
                            'recommendation': 'Enable access logging for traffic analysis and debugging'
                        })
            except ClientError:
                pass
        
        return {
            'findings': findings,
            'total_findings': len(findings)
        }
    
    def run_full_compliance_check(self) -> Dict[str, Any]:
        """Run comprehensive compliance checks."""
        self.service_status = {}  # Reset status
        
        well_architected = self.check_well_architected_practices()
        tagging = self.check_tagging_compliance()
        backup = self.check_backup_policies()
        multi_az = self.check_multi_az_deployments()
        logging = self.check_logging_and_monitoring()
        
        # Combine all findings
        all_findings = (
            well_architected.get('findings', []) +
            tagging.get('findings', []) +
            backup.get('findings', []) +
            multi_az.get('findings', []) +
            logging.get('findings', [])
        )
        
        # Calculate summary
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        for finding in all_findings:
            severity = finding.get('severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        results = {
            'check_time': datetime.now().isoformat(),
            'well_architected': well_architected,
            'tagging_compliance': tagging,
            'backup_policies': backup,
            'multi_az_deployments': multi_az,
            'logging_monitoring': logging,
            'summary': {
                'total_findings': len(all_findings),
                'severity_breakdown': severity_counts,
                'pillar_scores': well_architected.get('pillar_scores', {}),
                'overall_compliance_score': well_architected.get('overall_score', 0),
                'tagging_compliance_rate': tagging.get('summary', {}).get('compliance_rate', 0)
            },
            'service_status': self.service_status
        }
        
        return results
    
    def get_ai_recommendations(self, compliance_results: Dict[str, Any]) -> Optional[str]:
        """Get AI-powered compliance recommendations."""
        if not self.openai_client:
            return None
        
        # Prepare summary for AI
        summary = {
            'pillar_scores': compliance_results.get('summary', {}).get('pillar_scores', {}),
            'overall_score': compliance_results.get('summary', {}).get('overall_compliance_score', 0),
            'severity_breakdown': compliance_results.get('summary', {}).get('severity_breakdown', {}),
            'total_findings': compliance_results.get('summary', {}).get('total_findings', 0),
            'tagging_compliance': compliance_results.get('summary', {}).get('tagging_compliance_rate', 0)
        }
        
        # Include top critical/high findings
        all_findings = []
        for category in ['well_architected', 'tagging_compliance', 'backup_policies', 'multi_az_deployments', 'logging_monitoring']:
            findings = compliance_results.get(category, {}).get('findings', [])
            all_findings.extend([f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']][:5])
        
        summary['critical_findings'] = all_findings[:10]
        
        system_prompt = """You are an AWS Well-Architected Framework expert. Analyze the compliance check results and provide:

1. **Executive Summary**: Overall compliance posture assessment
2. **Critical Gaps**: Most urgent compliance issues to address
3. **Pillar-Specific Recommendations**: Improvements for each Well-Architected pillar
4. **Compliance Roadmap**: Prioritized remediation plan
5. **Quick Wins**: Easy improvements with high impact

Reference specific AWS best practices and Well-Architected Framework guidance.
Format your response in clear Markdown with headers and bullet points."""

        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze this AWS compliance data:\n\n{json.dumps(summary, indent=2, default=str)}"}
                ],
                max_tokens=2000,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating AI recommendations: {str(e)}"
