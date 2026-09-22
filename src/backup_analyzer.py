"""
AWS Backup & Disaster Recovery Analyzer.
Analyzes RDS snapshots, S3 versioning, cross-region replication, and DR readiness.
"""

import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from openai import OpenAI
import os
import json
from botocore.exceptions import ClientError, NoCredentialsError


class AWSBackupAnalyzer:
    """Analyzes backup and disaster recovery configurations."""
    
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
    
    def _get_client(self, service: str, region: str = None):
        """Get a boto3 client for a specific service with graceful fallback."""
        try:
            return boto3.client(service, region_name=region or self.region)
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
    
    def get_rds_snapshot_inventory(self) -> Dict[str, Any]:
        """Get inventory of all RDS snapshots with age analysis."""
        rds = self._get_client('rds')
        if not rds:
            return {'snapshots': [], 'error': 'RDS client unavailable'}
        
        snapshots = []
        instances_without_recent_backup = []
        
        # Get all manual snapshots
        try:
            manual_response = rds.describe_db_snapshots(SnapshotType='manual')
            for snap in manual_response.get('DBSnapshots', []):
                age_days = (datetime.now(snap['SnapshotCreateTime'].tzinfo) - snap['SnapshotCreateTime']).days if snap.get('SnapshotCreateTime') else 0
                
                snapshots.append({
                    'snapshot_id': snap['DBSnapshotIdentifier'],
                    'db_instance': snap.get('DBInstanceIdentifier', 'Unknown'),
                    'type': 'manual',
                    'status': snap.get('Status', 'unknown'),
                    'engine': snap.get('Engine', 'Unknown'),
                    'allocated_storage_gb': snap.get('AllocatedStorage', 0),
                    'created': snap.get('SnapshotCreateTime', '').isoformat() if snap.get('SnapshotCreateTime') else None,
                    'age_days': age_days,
                    'encrypted': snap.get('Encrypted', False),
                    'kms_key_id': snap.get('KmsKeyId')
                })
        except ClientError as e:
            self.service_status['rds_manual_snapshots'] = f"Error: {e}"
        
        # Get automated snapshots
        try:
            auto_response = rds.describe_db_snapshots(SnapshotType='automated')
            for snap in auto_response.get('DBSnapshots', []):
                age_days = (datetime.now(snap['SnapshotCreateTime'].tzinfo) - snap['SnapshotCreateTime']).days if snap.get('SnapshotCreateTime') else 0
                
                snapshots.append({
                    'snapshot_id': snap['DBSnapshotIdentifier'],
                    'db_instance': snap.get('DBInstanceIdentifier', 'Unknown'),
                    'type': 'automated',
                    'status': snap.get('Status', 'unknown'),
                    'engine': snap.get('Engine', 'Unknown'),
                    'allocated_storage_gb': snap.get('AllocatedStorage', 0),
                    'created': snap.get('SnapshotCreateTime', '').isoformat() if snap.get('SnapshotCreateTime') else None,
                    'age_days': age_days,
                    'encrypted': snap.get('Encrypted', False)
                })
        except ClientError as e:
            self.service_status['rds_auto_snapshots'] = f"Error: {e}"
        
        # Get cluster snapshots (Aurora)
        try:
            cluster_response = rds.describe_db_cluster_snapshots()
            for snap in cluster_response.get('DBClusterSnapshots', []):
                age_days = (datetime.now(snap['SnapshotCreateTime'].tzinfo) - snap['SnapshotCreateTime']).days if snap.get('SnapshotCreateTime') else 0
                
                snapshots.append({
                    'snapshot_id': snap['DBClusterSnapshotIdentifier'],
                    'db_instance': snap.get('DBClusterIdentifier', 'Unknown'),
                    'type': 'cluster_' + snap.get('SnapshotType', 'manual'),
                    'status': snap.get('Status', 'unknown'),
                    'engine': snap.get('Engine', 'Unknown'),
                    'allocated_storage_gb': snap.get('AllocatedStorage', 0),
                    'created': snap.get('SnapshotCreateTime', '').isoformat() if snap.get('SnapshotCreateTime') else None,
                    'age_days': age_days,
                    'encrypted': snap.get('StorageEncrypted', False)
                })
        except ClientError as e:
            self.service_status['rds_cluster_snapshots'] = f"Error: {e}"
        
        # Check for instances without recent backups
        try:
            instances = rds.describe_db_instances()
            snapshot_by_instance = {}
            for snap in snapshots:
                instance = snap.get('db_instance')
                if instance not in snapshot_by_instance or snap['age_days'] < snapshot_by_instance[instance]:
                    snapshot_by_instance[instance] = snap['age_days']
            
            for db in instances.get('DBInstances', []):
                db_id = db['DBInstanceIdentifier']
                latest_backup_age = snapshot_by_instance.get(db_id, float('inf'))
                
                if latest_backup_age > 7:
                    instances_without_recent_backup.append({
                        'db_identifier': db_id,
                        'latest_backup_age_days': latest_backup_age if latest_backup_age != float('inf') else None,
                        'backup_retention_period': db.get('BackupRetentionPeriod', 0),
                        'has_no_backups': latest_backup_age == float('inf')
                    })
        except ClientError:
            pass
        
        # Sort snapshots by age
        snapshots.sort(key=lambda x: x['age_days'])
        
        # Calculate summary
        total_storage = sum(s['allocated_storage_gb'] for s in snapshots)
        old_snapshots = [s for s in snapshots if s['age_days'] > 30 and s['type'] == 'manual']
        
        return {
            'snapshots': snapshots,
            'instances_without_recent_backup': instances_without_recent_backup,
            'summary': {
                'total_snapshots': len(snapshots),
                'manual_snapshots': len([s for s in snapshots if s['type'] == 'manual']),
                'automated_snapshots': len([s for s in snapshots if s['type'] == 'automated']),
                'total_storage_gb': total_storage,
                'old_manual_snapshots': len(old_snapshots),
                'encrypted_snapshots': len([s for s in snapshots if s['encrypted']])
            }
        }
    
    def get_s3_versioning_status(self) -> Dict[str, Any]:
        """Check S3 bucket versioning and lifecycle configurations."""
        s3 = self._get_client('s3')
        if not s3:
            return {'buckets': [], 'error': 'S3 client unavailable'}
        
        buckets = []
        
        response = self._safe_api_call('s3', s3.list_buckets)
        if not response:
            return {'buckets': buckets, 'error': 'Could not list buckets'}
        
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            
            bucket_info = {
                'bucket_name': bucket_name,
                'created': bucket.get('CreationDate', '').isoformat() if bucket.get('CreationDate') else None,
                'versioning': 'Disabled',
                'mfa_delete': False,
                'lifecycle_rules': 0,
                'replication': False,
                'replication_destinations': []
            }
            
            # Check versioning
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                bucket_info['versioning'] = versioning.get('Status', 'Disabled')
                bucket_info['mfa_delete'] = versioning.get('MFADelete') == 'Enabled'
            except ClientError:
                pass
            
            # Check lifecycle rules
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                bucket_info['lifecycle_rules'] = len(lifecycle.get('Rules', []))
                
                # Analyze lifecycle rules
                rules_summary = []
                for rule in lifecycle.get('Rules', []):
                    rule_info = {
                        'id': rule.get('ID', 'Unnamed'),
                        'status': rule.get('Status', 'Unknown'),
                        'transitions': [],
                        'expiration': None
                    }
                    
                    for transition in rule.get('Transitions', []):
                        rule_info['transitions'].append({
                            'days': transition.get('Days'),
                            'storage_class': transition.get('StorageClass')
                        })
                    
                    if rule.get('Expiration'):
                        rule_info['expiration'] = rule['Expiration'].get('Days')
                    
                    rules_summary.append(rule_info)
                
                bucket_info['lifecycle_rules_detail'] = rules_summary
            except ClientError as e:
                if 'NoSuchLifecycleConfiguration' not in str(e):
                    pass
            
            # Check replication
            try:
                replication = s3.get_bucket_replication(Bucket=bucket_name)
                bucket_info['replication'] = True
                
                for rule in replication.get('ReplicationConfiguration', {}).get('Rules', []):
                    dest = rule.get('Destination', {})
                    bucket_info['replication_destinations'].append({
                        'bucket': dest.get('Bucket', '').split(':')[-1],
                        'storage_class': dest.get('StorageClass', 'STANDARD'),
                        'status': rule.get('Status', 'Unknown')
                    })
            except ClientError as e:
                if 'ReplicationConfigurationNotFoundError' not in str(e):
                    pass
            
            buckets.append(bucket_info)
        
        # Calculate summary
        versioning_enabled = len([b for b in buckets if b['versioning'] == 'Enabled'])
        with_lifecycle = len([b for b in buckets if b['lifecycle_rules'] > 0])
        with_replication = len([b for b in buckets if b['replication']])
        
        return {
            'buckets': buckets,
            'summary': {
                'total_buckets': len(buckets),
                'versioning_enabled': versioning_enabled,
                'versioning_disabled': len(buckets) - versioning_enabled,
                'with_lifecycle_rules': with_lifecycle,
                'with_replication': with_replication,
                'mfa_delete_enabled': len([b for b in buckets if b['mfa_delete']])
            }
        }
    
    def check_cross_region_replication(self) -> Dict[str, Any]:
        """Check cross-region replication configurations."""
        findings = []
        
        # Check S3 CRR
        s3_status = self.get_s3_versioning_status()
        for bucket in s3_status.get('buckets', []):
            if bucket['replication']:
                for dest in bucket.get('replication_destinations', []):
                    findings.append({
                        'type': 'S3_CRR',
                        'source': bucket['bucket_name'],
                        'destination': dest['bucket'],
                        'status': dest['status'],
                        'storage_class': dest['storage_class']
                    })
        
        # Check RDS cross-region read replicas
        rds = self._get_client('rds')
        if rds:
            try:
                instances = rds.describe_db_instances()
                for db in instances.get('DBInstances', []):
                    read_replicas = db.get('ReadReplicaDBInstanceIdentifiers', [])
                    source_region = db.get('SourceRegion')
                    
                    if source_region:
                        findings.append({
                            'type': 'RDS_CROSS_REGION_REPLICA',
                            'source_region': source_region,
                            'replica': db['DBInstanceIdentifier'],
                            'destination_region': self.region,
                            'engine': db.get('Engine'),
                            'status': db.get('DBInstanceStatus')
                        })
            except ClientError:
                pass
        
        # Check DynamoDB Global Tables
        dynamodb = self._get_client('dynamodb')
        if dynamodb:
            try:
                tables = dynamodb.list_tables()
                for table_name in tables.get('TableNames', []):
                    table = dynamodb.describe_table(TableName=table_name)
                    global_table = table.get('Table', {}).get('GlobalTableVersion')
                    replicas = table.get('Table', {}).get('Replicas', [])
                    
                    if replicas:
                        for replica in replicas:
                            findings.append({
                                'type': 'DYNAMODB_GLOBAL_TABLE',
                                'table_name': table_name,
                                'replica_region': replica.get('RegionName'),
                                'status': replica.get('ReplicaStatus')
                            })
            except ClientError:
                pass
        
        return {
            'replication_configs': findings,
            'summary': {
                's3_crr_count': len([f for f in findings if f['type'] == 'S3_CRR']),
                'rds_cross_region_count': len([f for f in findings if f['type'] == 'RDS_CROSS_REGION_REPLICA']),
                'dynamodb_global_tables': len([f for f in findings if f['type'] == 'DYNAMODB_GLOBAL_TABLE'])
            }
        }
    
    def get_ec2_ami_backup_status(self) -> Dict[str, Any]:
        """Check EC2 AMI backups and EBS snapshots."""
        ec2 = self._get_client('ec2')
        if not ec2:
            return {'amis': [], 'snapshots': [], 'error': 'EC2 client unavailable'}
        
        amis = []
        snapshots = []
        instances_without_ami = []
        
        # Get owned AMIs
        try:
            ami_response = ec2.describe_images(Owners=['self'])
            for ami in ami_response.get('Images', []):
                creation_date = ami.get('CreationDate', '')
                age_days = 0
                if creation_date:
                    try:
                        created = datetime.strptime(creation_date[:19], '%Y-%m-%dT%H:%M:%S')
                        age_days = (datetime.now() - created).days
                    except ValueError:
                        pass
                
                amis.append({
                    'ami_id': ami['ImageId'],
                    'name': ami.get('Name', 'Unnamed'),
                    'state': ami.get('State', 'unknown'),
                    'created': creation_date,
                    'age_days': age_days,
                    'architecture': ami.get('Architecture'),
                    'root_device_type': ami.get('RootDeviceType'),
                    'block_devices': len(ami.get('BlockDeviceMappings', []))
                })
        except ClientError as e:
            self.service_status['ec2_amis'] = f"Error: {e}"
        
        # Get EBS snapshots
        try:
            snap_response = ec2.describe_snapshots(OwnerIds=['self'])
            for snap in snap_response.get('Snapshots', []):
                age_days = 0
                if snap.get('StartTime'):
                    age_days = (datetime.now(snap['StartTime'].tzinfo) - snap['StartTime']).days
                
                snapshots.append({
                    'snapshot_id': snap['SnapshotId'],
                    'volume_id': snap.get('VolumeId', 'Unknown'),
                    'state': snap.get('State', 'unknown'),
                    'volume_size_gb': snap.get('VolumeSize', 0),
                    'created': snap.get('StartTime', '').isoformat() if snap.get('StartTime') else None,
                    'age_days': age_days,
                    'encrypted': snap.get('Encrypted', False),
                    'description': snap.get('Description', '')[:100]
                })
        except ClientError as e:
            self.service_status['ec2_snapshots'] = f"Error: {e}"
        
        # Check for running instances without recent AMI
        try:
            instances = ec2.describe_instances(
                Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
            )
            
            # Build AMI map by name prefix (assuming naming convention includes instance info)
            ami_instances = set()
            for ami in amis:
                # Try to extract instance ID from AMI name
                name = ami.get('name', '')
                for tag_prefix in ['backup-', 'ami-', 'image-']:
                    if tag_prefix in name.lower():
                        parts = name.split('-')
                        for part in parts:
                            if part.startswith('i-'):
                                ami_instances.add(part)
            
            for reservation in instances.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    instance_name = ''
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                    
                    # Check if instance appears important
                    important_keywords = ['prod', 'production', 'database', 'critical', 'master']
                    is_important = any(kw in instance_name.lower() for kw in important_keywords)
                    
                    if is_important and instance_id not in ami_instances:
                        instances_without_ami.append({
                            'instance_id': instance_id,
                            'instance_name': instance_name,
                            'instance_type': instance.get('InstanceType'),
                            'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else None
                        })
        except ClientError:
            pass
        
        # Sort by age
        amis.sort(key=lambda x: x['age_days'])
        snapshots.sort(key=lambda x: x['age_days'])
        
        # Calculate summary
        old_amis = len([a for a in amis if a['age_days'] > 90])
        old_snapshots = len([s for s in snapshots if s['age_days'] > 90])
        total_snapshot_storage = sum(s['volume_size_gb'] for s in snapshots)
        
        return {
            'amis': amis,
            'snapshots': snapshots,
            'instances_without_ami': instances_without_ami,
            'summary': {
                'total_amis': len(amis),
                'old_amis_90_days': old_amis,
                'total_snapshots': len(snapshots),
                'old_snapshots_90_days': old_snapshots,
                'total_snapshot_storage_gb': total_snapshot_storage,
                'instances_without_backup': len(instances_without_ami)
            }
        }
    
    def get_aws_backup_status(self) -> Dict[str, Any]:
        """Get AWS Backup service status and vault information."""
        backup = self._get_client('backup')
        if not backup:
            return {'vaults': [], 'plans': [], 'error': 'AWS Backup client unavailable'}
        
        vaults = []
        plans = []
        protected_resources = []
        
        # Get backup vaults
        try:
            vault_response = backup.list_backup_vaults()
            for vault in vault_response.get('BackupVaultList', []):
                vault_info = {
                    'vault_name': vault['BackupVaultName'],
                    'vault_arn': vault.get('BackupVaultArn'),
                    'creation_date': vault.get('CreationDate', '').isoformat() if vault.get('CreationDate') else None,
                    'encryption_key': vault.get('EncryptionKeyArn'),
                    'recovery_points': vault.get('NumberOfRecoveryPoints', 0)
                }
                vaults.append(vault_info)
        except ClientError as e:
            self.service_status['backup_vaults'] = f"Error: {e}"
        
        # Get backup plans
        try:
            plans_response = backup.list_backup_plans()
            for plan in plans_response.get('BackupPlansList', []):
                plan_id = plan['BackupPlanId']
                
                # Get plan details
                try:
                    detail = backup.get_backup_plan(BackupPlanId=plan_id)
                    rules = detail.get('BackupPlan', {}).get('Rules', [])
                    
                    plan_info = {
                        'plan_id': plan_id,
                        'plan_name': plan.get('BackupPlanName'),
                        'creation_date': plan.get('CreationDate', '').isoformat() if plan.get('CreationDate') else None,
                        'last_execution': plan.get('LastExecutionDate', '').isoformat() if plan.get('LastExecutionDate') else None,
                        'rules_count': len(rules),
                        'rules': []
                    }
                    
                    for rule in rules:
                        plan_info['rules'].append({
                            'rule_name': rule.get('RuleName'),
                            'target_vault': rule.get('TargetBackupVaultName'),
                            'schedule': rule.get('ScheduleExpression'),
                            'lifecycle_delete_days': rule.get('Lifecycle', {}).get('DeleteAfterDays'),
                            'lifecycle_cold_storage_days': rule.get('Lifecycle', {}).get('MoveToColdStorageAfterDays')
                        })
                    
                    plans.append(plan_info)
                except ClientError:
                    plans.append({
                        'plan_id': plan_id,
                        'plan_name': plan.get('BackupPlanName')
                    })
        except ClientError as e:
            self.service_status['backup_plans'] = f"Error: {e}"
        
        # Get protected resources
        try:
            paginator = backup.get_paginator('list_protected_resources')
            for page in paginator.paginate():
                for resource in page.get('Results', []):
                    protected_resources.append({
                        'resource_arn': resource.get('ResourceArn'),
                        'resource_type': resource.get('ResourceType'),
                        'last_backup': resource.get('LastBackupTime', '').isoformat() if resource.get('LastBackupTime') else None
                    })
        except ClientError as e:
            self.service_status['protected_resources'] = f"Error: {e}"
        
        return {
            'vaults': vaults,
            'plans': plans,
            'protected_resources': protected_resources,
            'summary': {
                'total_vaults': len(vaults),
                'total_plans': len(plans),
                'total_protected_resources': len(protected_resources),
                'total_recovery_points': sum(v.get('recovery_points', 0) for v in vaults)
            }
        }
    
    def calculate_dr_readiness_score(self) -> Dict[str, Any]:
        """Calculate a disaster recovery readiness score."""
        score = 100
        findings = []
        
        # Check RDS backups
        rds_status = self.get_rds_snapshot_inventory()
        instances_without_backup = rds_status.get('instances_without_recent_backup', [])
        if instances_without_backup:
            deduction = min(len(instances_without_backup) * 10, 30)
            score -= deduction
            findings.append({
                'category': 'RDS Backups',
                'issue': f'{len(instances_without_backup)} database(s) without recent backup',
                'deduction': deduction,
                'severity': 'HIGH'
            })
        
        # Check S3 versioning
        s3_status = self.get_s3_versioning_status()
        s3_summary = s3_status.get('summary', {})
        versioning_disabled = s3_summary.get('versioning_disabled', 0)
        if versioning_disabled > 0:
            deduction = min(versioning_disabled * 2, 15)
            score -= deduction
            findings.append({
                'category': 'S3 Versioning',
                'issue': f'{versioning_disabled} bucket(s) without versioning',
                'deduction': deduction,
                'severity': 'MEDIUM'
            })
        
        # Check cross-region replication
        crr_status = self.check_cross_region_replication()
        crr_summary = crr_status.get('summary', {})
        if crr_summary.get('s3_crr_count', 0) == 0 and s3_summary.get('total_buckets', 0) > 0:
            score -= 10
            findings.append({
                'category': 'Cross-Region Replication',
                'issue': 'No S3 cross-region replication configured',
                'deduction': 10,
                'severity': 'MEDIUM'
            })
        
        # Check EC2 AMI backups
        ec2_status = self.get_ec2_ami_backup_status()
        instances_without_ami = ec2_status.get('instances_without_ami', [])
        if instances_without_ami:
            deduction = min(len(instances_without_ami) * 5, 20)
            score -= deduction
            findings.append({
                'category': 'EC2 AMI Backups',
                'issue': f'{len(instances_without_ami)} critical instance(s) without AMI backup',
                'deduction': deduction,
                'severity': 'HIGH'
            })
        
        # Check AWS Backup
        backup_status = self.get_aws_backup_status()
        backup_summary = backup_status.get('summary', {})
        if backup_summary.get('total_plans', 0) == 0:
            score -= 15
            findings.append({
                'category': 'AWS Backup',
                'issue': 'No AWS Backup plans configured',
                'deduction': 15,
                'severity': 'HIGH'
            })
        
        # Determine DR readiness level
        if score >= 90:
            readiness_level = 'EXCELLENT'
            status_color = 'green'
        elif score >= 70:
            readiness_level = 'GOOD'
            status_color = 'green'
        elif score >= 50:
            readiness_level = 'FAIR'
            status_color = 'yellow'
        elif score >= 30:
            readiness_level = 'POOR'
            status_color = 'orange'
        else:
            readiness_level = 'CRITICAL'
            status_color = 'red'
        
        return {
            'score': max(0, score),
            'readiness_level': readiness_level,
            'status_color': status_color,
            'findings': findings,
            'recommendations': self._generate_dr_recommendations(findings)
        }
    
    def _generate_dr_recommendations(self, findings: List[Dict]) -> List[str]:
        """Generate DR recommendations based on findings."""
        recommendations = []
        
        categories_with_issues = set(f['category'] for f in findings)
        
        if 'RDS Backups' in categories_with_issues:
            recommendations.append('Enable automated backups for all RDS instances with at least 7-day retention')
            recommendations.append('Create manual snapshots before major changes')
        
        if 'S3 Versioning' in categories_with_issues:
            recommendations.append('Enable versioning on all S3 buckets containing important data')
            recommendations.append('Configure lifecycle policies to manage version storage costs')
        
        if 'Cross-Region Replication' in categories_with_issues:
            recommendations.append('Set up S3 cross-region replication for critical buckets')
            recommendations.append('Consider RDS cross-region read replicas for disaster recovery')
        
        if 'EC2 AMI Backups' in categories_with_issues:
            recommendations.append('Create AMI backups of critical EC2 instances')
            recommendations.append('Set up automated AMI creation using AWS Backup or Lambda')
        
        if 'AWS Backup' in categories_with_issues:
            recommendations.append('Create AWS Backup plans for centralized backup management')
            recommendations.append('Define backup policies for different resource types')
        
        if not recommendations:
            recommendations.append('Continue monitoring backup health')
            recommendations.append('Regularly test restore procedures')
            recommendations.append('Document DR runbooks')
        
        return recommendations
    
    def run_full_backup_analysis(self) -> Dict[str, Any]:
        """Run comprehensive backup and DR analysis."""
        self.service_status = {}  # Reset status
        
        results = {
            'analysis_time': datetime.now().isoformat(),
            'rds_snapshots': self.get_rds_snapshot_inventory(),
            's3_versioning': self.get_s3_versioning_status(),
            'cross_region_replication': self.check_cross_region_replication(),
            'ec2_backups': self.get_ec2_ami_backup_status(),
            'aws_backup': self.get_aws_backup_status(),
            'dr_readiness': self.calculate_dr_readiness_score(),
            'service_status': self.service_status
        }
        
        return results
    
    def get_ai_recommendations(self, backup_results: Dict[str, Any]) -> Optional[str]:
        """Get AI-powered backup and DR recommendations."""
        if not self.openai_client:
            return None
        
        # Prepare summary for AI
        summary = {
            'dr_readiness': backup_results.get('dr_readiness', {}),
            'rds_summary': backup_results.get('rds_snapshots', {}).get('summary', {}),
            's3_summary': backup_results.get('s3_versioning', {}).get('summary', {}),
            'ec2_summary': backup_results.get('ec2_backups', {}).get('summary', {}),
            'backup_summary': backup_results.get('aws_backup', {}).get('summary', {})
        }
        
        system_prompt = """You are an AWS disaster recovery expert. Analyze the backup status and provide:

1. **DR Readiness Assessment**: Overall evaluation of disaster recovery posture
2. **Critical Gaps**: Most urgent backup/DR issues to address
3. **Recovery Time Objectives**: Recommendations for RTO/RPO based on current setup
4. **Cost-Effective Improvements**: High-impact, low-cost DR improvements
5. **DR Testing Plan**: Recommendations for testing backup and recovery procedures

Focus on practical, actionable recommendations.
Format your response in clear Markdown with headers and bullet points."""

        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze this AWS backup/DR data:\n\n{json.dumps(summary, indent=2, default=str)}"}
                ],
                max_tokens=1500,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating AI recommendations: {str(e)}"
