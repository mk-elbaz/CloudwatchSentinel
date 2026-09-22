"""
AWS Security Analyzer with AI-powered recommendations.
Scans for security misconfigurations across AWS services.
"""

import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from openai import OpenAI
import os
import json
from botocore.exceptions import ClientError, NoCredentialsError


class AWSSecurityAnalyzer:
    """Analyzes AWS security posture and provides AI-powered hardening recommendations."""
    
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
        """Test connectivity to security-related AWS services."""
        results = {}
        
        # Test EC2 (for security groups)
        try:
            ec2 = self._get_client('ec2')
            if ec2:
                ec2.describe_security_groups(MaxResults=5)
                results['ec2'] = True
        except Exception:
            results['ec2'] = False
        
        # Test S3
        try:
            s3 = self._get_client('s3')
            if s3:
                s3.list_buckets()
                results['s3'] = True
        except Exception:
            results['s3'] = False
        
        # Test IAM
        try:
            iam = self._get_client('iam')
            if iam:
                iam.list_users(MaxItems=1)
                results['iam'] = True
        except Exception:
            results['iam'] = False
        
        # Test ACM
        try:
            acm = self._get_client('acm')
            if acm:
                acm.list_certificates(MaxItems=1)
                results['acm'] = True
        except Exception:
            results['acm'] = False
        
        return results
    
    def scan_security_groups(self) -> List[Dict[str, Any]]:
        """Scan EC2 security groups for overly permissive rules."""
        findings = []
        ec2 = self._get_client('ec2')
        if not ec2:
            return findings
        
        response = self._safe_api_call('ec2', ec2.describe_security_groups)
        if not response:
            return findings
        
        # High-risk ports that should never be open to 0.0.0.0/0
        high_risk_ports = {
            22: 'SSH',
            3389: 'RDP',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            27017: 'MongoDB',
            6379: 'Redis',
            9200: 'Elasticsearch',
            11211: 'Memcached',
            23: 'Telnet',
            21: 'FTP',
            445: 'SMB',
            135: 'RPC',
            139: 'NetBIOS'
        }
        
        for sg in response.get('SecurityGroups', []):
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', 'Unknown')
            vpc_id = sg.get('VpcId', 'EC2-Classic')
            
            # Check inbound rules
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 65535)
                protocol = rule.get('IpProtocol', '-1')
                
                # Check for open CIDR ranges
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    
                    # Open to the world
                    if cidr in ['0.0.0.0/0', '::/0']:
                        # All traffic open
                        if protocol == '-1':
                            findings.append({
                                'type': 'OPEN_ALL_TRAFFIC',
                                'severity': 'CRITICAL',
                                'resource_type': 'SecurityGroup',
                                'resource_id': sg_id,
                                'resource_name': sg_name,
                                'vpc_id': vpc_id,
                                'title': f'Security group allows all inbound traffic from anywhere',
                                'description': f'Security group {sg_name} ({sg_id}) allows all protocols and ports from {cidr}',
                                'recommendation': 'Restrict inbound rules to specific ports and IP ranges required for your application'
                            })
                        # High-risk port open
                        elif from_port in high_risk_ports or to_port in high_risk_ports:
                            port = from_port if from_port in high_risk_ports else to_port
                            service = high_risk_ports.get(port, 'Unknown')
                            findings.append({
                                'type': 'OPEN_HIGH_RISK_PORT',
                                'severity': 'HIGH',
                                'resource_type': 'SecurityGroup',
                                'resource_id': sg_id,
                                'resource_name': sg_name,
                                'vpc_id': vpc_id,
                                'port': port,
                                'service': service,
                                'title': f'{service} port {port} open to the internet',
                                'description': f'Security group {sg_name} ({sg_id}) exposes {service} (port {port}) to {cidr}',
                                'recommendation': f'Restrict {service} access to specific IP ranges or use a VPN/bastion host'
                            })
                        # Port range open
                        elif from_port != to_port and (to_port - from_port) > 100:
                            findings.append({
                                'type': 'WIDE_PORT_RANGE',
                                'severity': 'MEDIUM',
                                'resource_type': 'SecurityGroup',
                                'resource_id': sg_id,
                                'resource_name': sg_name,
                                'vpc_id': vpc_id,
                                'port_range': f'{from_port}-{to_port}',
                                'title': f'Wide port range {from_port}-{to_port} open to internet',
                                'description': f'Security group {sg_name} ({sg_id}) allows ports {from_port}-{to_port} from {cidr}',
                                'recommendation': 'Restrict to only the specific ports required for your application'
                            })
                
                # Check for IPv6 open ranges
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    cidr = ipv6_range.get('CidrIpv6', '')
                    if cidr == '::/0':
                        if protocol == '-1' or from_port in high_risk_ports:
                            port_info = f"port {from_port}" if from_port else "all ports"
                            findings.append({
                                'type': 'OPEN_IPV6',
                                'severity': 'HIGH',
                                'resource_type': 'SecurityGroup',
                                'resource_id': sg_id,
                                'resource_name': sg_name,
                                'vpc_id': vpc_id,
                                'title': f'Security group allows IPv6 traffic from anywhere on {port_info}',
                                'description': f'Security group {sg_name} ({sg_id}) is open to all IPv6 addresses',
                                'recommendation': 'Restrict IPv6 inbound rules to specific ranges if IPv6 is required'
                            })
        
        return findings
    
    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """Scan S3 buckets for public access and misconfigurations."""
        findings = []
        s3 = self._get_client('s3')
        if not s3:
            return findings
        
        response = self._safe_api_call('s3', s3.list_buckets)
        if not response:
            return findings
        
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            
            # Check public access block
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab.get('PublicAccessBlockConfiguration', {})
                
                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    findings.append({
                        'type': 'S3_PUBLIC_ACCESS_NOT_BLOCKED',
                        'severity': 'MEDIUM',
                        'resource_type': 'S3Bucket',
                        'resource_id': bucket_name,
                        'title': f'S3 bucket does not block all public access',
                        'description': f'Bucket {bucket_name} has incomplete public access block settings',
                        'recommendation': 'Enable all four public access block settings unless public access is explicitly required',
                        'current_settings': config
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    findings.append({
                        'type': 'S3_NO_PUBLIC_ACCESS_BLOCK',
                        'severity': 'HIGH',
                        'resource_type': 'S3Bucket',
                        'resource_id': bucket_name,
                        'title': f'S3 bucket has no public access block configuration',
                        'description': f'Bucket {bucket_name} has no public access block settings configured',
                        'recommendation': 'Configure public access block to prevent accidental public exposure'
                    })
            
            # Check bucket ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    uri = grantee.get('URI', '')
                    
                    # Check for public access via ACL
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        permission = grant.get('Permission', 'Unknown')
                        findings.append({
                            'type': 'S3_PUBLIC_ACL',
                            'severity': 'CRITICAL',
                            'resource_type': 'S3Bucket',
                            'resource_id': bucket_name,
                            'title': f'S3 bucket has public ACL granting {permission}',
                            'description': f'Bucket {bucket_name} grants {permission} to {"all users" if "AllUsers" in uri else "authenticated AWS users"}',
                            'recommendation': 'Remove public ACL grants and use bucket policies with specific principal restrictions'
                        })
            except ClientError:
                pass
            
            # Check bucket encryption
            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    findings.append({
                        'type': 'S3_NO_ENCRYPTION',
                        'severity': 'MEDIUM',
                        'resource_type': 'S3Bucket',
                        'resource_id': bucket_name,
                        'title': f'S3 bucket does not have default encryption enabled',
                        'description': f'Bucket {bucket_name} does not enforce server-side encryption',
                        'recommendation': 'Enable default encryption using SSE-S3 or SSE-KMS'
                    })
            
            # Check versioning
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    findings.append({
                        'type': 'S3_NO_VERSIONING',
                        'severity': 'LOW',
                        'resource_type': 'S3Bucket',
                        'resource_id': bucket_name,
                        'title': f'S3 bucket versioning is not enabled',
                        'description': f'Bucket {bucket_name} does not have versioning enabled for data protection',
                        'recommendation': 'Enable versioning to protect against accidental deletions and overwrites'
                    })
            except ClientError:
                pass
        
        return findings
    
    def scan_iam_policies(self) -> List[Dict[str, Any]]:
        """Scan IAM for overly permissive policies and risky configurations."""
        findings = []
        iam = self._get_client('iam')
        if not iam:
            return findings
        
        # Scan IAM users
        users_response = self._safe_api_call('iam', iam.list_users)
        if users_response:
            for user in users_response.get('Users', []):
                username = user['UserName']
                user_arn = user['Arn']
                
                # Check for users with console access but no MFA
                try:
                    login_profile = iam.get_login_profile(UserName=username)
                    # User has console access, check MFA
                    mfa_devices = iam.list_mfa_devices(UserName=username)
                    if not mfa_devices.get('MFADevices', []):
                        findings.append({
                            'type': 'IAM_NO_MFA',
                            'severity': 'HIGH',
                            'resource_type': 'IAMUser',
                            'resource_id': username,
                            'title': f'IAM user has console access without MFA',
                            'description': f'User {username} can log into the AWS console but has no MFA device configured',
                            'recommendation': 'Enable MFA for all users with console access'
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchEntity':
                        pass  # User has no console access, which is fine
                
                # Check for inline policies with Admin access
                try:
                    inline_policies = iam.list_user_policies(UserName=username)
                    for policy_name in inline_policies.get('PolicyNames', []):
                        policy = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                        doc = policy.get('PolicyDocument', {})
                        if self._is_admin_policy(doc):
                            findings.append({
                                'type': 'IAM_ADMIN_INLINE_POLICY',
                                'severity': 'HIGH',
                                'resource_type': 'IAMUser',
                                'resource_id': username,
                                'title': f'IAM user has admin-level inline policy',
                                'description': f'User {username} has inline policy {policy_name} with administrative privileges',
                                'recommendation': 'Follow least privilege principle - grant only required permissions'
                            })
                except ClientError:
                    pass
                
                # Check attached policies
                try:
                    attached = iam.list_attached_user_policies(UserName=username)
                    for policy in attached.get('AttachedPolicies', []):
                        if policy['PolicyArn'].endswith('AdministratorAccess'):
                            findings.append({
                                'type': 'IAM_ADMIN_ATTACHED',
                                'severity': 'MEDIUM',
                                'resource_type': 'IAMUser',
                                'resource_id': username,
                                'title': f'IAM user has AdministratorAccess policy attached',
                                'description': f'User {username} has full administrative access to the AWS account',
                                'recommendation': 'Use specific policies instead of AdministratorAccess where possible'
                            })
                except ClientError:
                    pass
                
                # Check for old access keys
                try:
                    keys = iam.list_access_keys(UserName=username)
                    for key in keys.get('AccessKeyMetadata', []):
                        key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                        if key_age > 90:
                            findings.append({
                                'type': 'IAM_OLD_ACCESS_KEY',
                                'severity': 'MEDIUM',
                                'resource_type': 'IAMAccessKey',
                                'resource_id': key['AccessKeyId'],
                                'resource_name': username,
                                'title': f'IAM access key is {key_age} days old',
                                'description': f'Access key {key["AccessKeyId"]} for user {username} was created {key_age} days ago',
                                'recommendation': 'Rotate access keys regularly (every 90 days recommended)',
                                'key_age_days': key_age
                            })
                except ClientError:
                    pass
        
        # Scan IAM roles
        roles_response = self._safe_api_call('iam', iam.list_roles)
        if roles_response:
            for role in roles_response.get('Roles', []):
                role_name = role['RoleName']
                
                # Skip AWS service-linked roles
                if role.get('Path', '').startswith('/aws-service-role/'):
                    continue
                
                # Check for overly permissive assume role policies
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                for statement in trust_policy.get('Statement', []):
                    principal = statement.get('Principal', {})
                    
                    # Check for wildcard principal
                    if principal == '*' or principal.get('AWS') == '*':
                        findings.append({
                            'type': 'IAM_ROLE_WILDCARD_PRINCIPAL',
                            'severity': 'CRITICAL',
                            'resource_type': 'IAMRole',
                            'resource_id': role_name,
                            'title': f'IAM role can be assumed by any AWS principal',
                            'description': f'Role {role_name} has a trust policy allowing any AWS account to assume it',
                            'recommendation': 'Restrict the Principal to specific accounts, services, or identities'
                        })
        
        return findings
    
    def _is_admin_policy(self, policy_doc: Dict) -> bool:
        """Check if a policy document grants admin-level access."""
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])
                
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                
                # Check for * actions on * resources
                if '*' in actions and '*' in resources:
                    return True
                if any(a.endswith(':*') for a in actions) and '*' in resources:
                    return True
        
        return False
    
    def scan_unused_credentials(self) -> List[Dict[str, Any]]:
        """Detect unused IAM credentials."""
        findings = []
        iam = self._get_client('iam')
        if not iam:
            return findings
        
        # Generate credential report
        try:
            iam.generate_credential_report()
            import time
            time.sleep(2)  # Wait for report generation
            
            report = iam.get_credential_report()
            import csv
            from io import StringIO
            
            content = report['Content'].decode('utf-8')
            reader = csv.DictReader(StringIO(content))
            
            for row in reader:
                username = row['user']
                
                # Skip root account for some checks
                if username == '<root_account>':
                    # Check if root has access keys
                    if row.get('access_key_1_active', 'false') == 'true':
                        findings.append({
                            'type': 'ROOT_ACCESS_KEY',
                            'severity': 'CRITICAL',
                            'resource_type': 'IAMUser',
                            'resource_id': 'root',
                            'title': 'Root account has active access keys',
                            'description': 'The AWS root account has active access keys which is a security risk',
                            'recommendation': 'Delete root account access keys and use IAM users instead'
                        })
                    continue
                
                # Check for unused password
                password_last_used = row.get('password_last_used', 'N/A')
                if row.get('password_enabled', 'false') == 'true' and password_last_used not in ['N/A', 'no_information']:
                    try:
                        last_used = datetime.strptime(password_last_used.split('T')[0], '%Y-%m-%d')
                        days_unused = (datetime.now() - last_used).days
                        if days_unused > 90:
                            findings.append({
                                'type': 'IAM_UNUSED_PASSWORD',
                                'severity': 'LOW',
                                'resource_type': 'IAMUser',
                                'resource_id': username,
                                'title': f'IAM user password unused for {days_unused} days',
                                'description': f'User {username} has not used their password in {days_unused} days',
                                'recommendation': 'Disable or delete unused credentials',
                                'days_unused': days_unused
                            })
                    except ValueError:
                        pass
                
                # Check for unused access keys
                for key_num in ['1', '2']:
                    if row.get(f'access_key_{key_num}_active', 'false') == 'true':
                        last_used = row.get(f'access_key_{key_num}_last_used_date', 'N/A')
                        if last_used not in ['N/A', 'no_information']:
                            try:
                                last_used_date = datetime.strptime(last_used.split('T')[0], '%Y-%m-%d')
                                days_unused = (datetime.now() - last_used_date).days
                                if days_unused > 90:
                                    findings.append({
                                        'type': 'IAM_UNUSED_ACCESS_KEY',
                                        'severity': 'MEDIUM',
                                        'resource_type': 'IAMAccessKey',
                                        'resource_id': f'{username}_key_{key_num}',
                                        'resource_name': username,
                                        'title': f'Access key unused for {days_unused} days',
                                        'description': f'User {username} access key {key_num} has not been used in {days_unused} days',
                                        'recommendation': 'Deactivate or delete unused access keys',
                                        'days_unused': days_unused
                                    })
                            except ValueError:
                                pass
                        elif last_used == 'N/A':
                            # Key exists but was never used
                            findings.append({
                                'type': 'IAM_NEVER_USED_KEY',
                                'severity': 'MEDIUM',
                                'resource_type': 'IAMAccessKey',
                                'resource_id': f'{username}_key_{key_num}',
                                'resource_name': username,
                                'title': f'Access key has never been used',
                                'description': f'User {username} has access key {key_num} that has never been used',
                                'recommendation': 'Delete access keys that are not needed'
                            })
        except ClientError as e:
            self.service_status['iam_credential_report'] = f"Error generating report: {e}"
        
        return findings
    
    def scan_ssl_certificates(self) -> List[Dict[str, Any]]:
        """Monitor SSL/TLS certificates for expiration."""
        findings = []
        acm = self._get_client('acm')
        if not acm:
            return findings
        
        response = self._safe_api_call('acm', acm.list_certificates)
        if not response:
            return findings
        
        for cert_summary in response.get('CertificateSummaryList', []):
            cert_arn = cert_summary['CertificateArn']
            domain = cert_summary.get('DomainName', 'Unknown')
            
            try:
                cert = acm.describe_certificate(CertificateArn=cert_arn)
                cert_detail = cert.get('Certificate', {})
                
                status = cert_detail.get('Status', 'Unknown')
                not_after = cert_detail.get('NotAfter')
                in_use = cert_detail.get('InUseBy', [])
                
                if not_after:
                    days_until_expiry = (not_after.replace(tzinfo=None) - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        severity = 'CRITICAL'
                        title = f'SSL certificate has EXPIRED'
                    elif days_until_expiry <= 7:
                        severity = 'CRITICAL'
                        title = f'SSL certificate expires in {days_until_expiry} days'
                    elif days_until_expiry <= 30:
                        severity = 'HIGH'
                        title = f'SSL certificate expires in {days_until_expiry} days'
                    elif days_until_expiry <= 60:
                        severity = 'MEDIUM'
                        title = f'SSL certificate expires in {days_until_expiry} days'
                    else:
                        continue  # Certificate is fine
                    
                    findings.append({
                        'type': 'SSL_CERTIFICATE_EXPIRING',
                        'severity': severity,
                        'resource_type': 'ACMCertificate',
                        'resource_id': cert_arn,
                        'resource_name': domain,
                        'title': title,
                        'description': f'Certificate for {domain} expires on {not_after.strftime("%Y-%m-%d")}',
                        'recommendation': 'Renew the certificate or enable auto-renewal if using ACM-issued certificates',
                        'days_until_expiry': days_until_expiry,
                        'in_use_by': in_use,
                        'status': status
                    })
                
                # Check for certificates with issues
                if status == 'FAILED':
                    findings.append({
                        'type': 'SSL_CERTIFICATE_FAILED',
                        'severity': 'HIGH',
                        'resource_type': 'ACMCertificate',
                        'resource_id': cert_arn,
                        'resource_name': domain,
                        'title': f'SSL certificate validation failed',
                        'description': f'Certificate for {domain} failed validation',
                        'recommendation': 'Review certificate validation requirements and re-request if needed'
                    })
                elif status == 'PENDING_VALIDATION':
                    findings.append({
                        'type': 'SSL_CERTIFICATE_PENDING',
                        'severity': 'LOW',
                        'resource_type': 'ACMCertificate',
                        'resource_id': cert_arn,
                        'resource_name': domain,
                        'title': f'SSL certificate pending validation',
                        'description': f'Certificate for {domain} is awaiting validation',
                        'recommendation': 'Complete DNS or email validation to activate the certificate'
                    })
            except ClientError:
                pass
        
        return findings
    
    def run_full_scan(self) -> Dict[str, Any]:
        """Run all security scans and return comprehensive results."""
        self.service_status = {}  # Reset status
        
        results = {
            'scan_time': datetime.now().isoformat(),
            'security_groups': self.scan_security_groups(),
            's3_buckets': self.scan_s3_buckets(),
            'iam_policies': self.scan_iam_policies(),
            'unused_credentials': self.scan_unused_credentials(),
            'ssl_certificates': self.scan_ssl_certificates(),
            'service_status': self.service_status
        }
        
        # Calculate summary
        all_findings = (
            results['security_groups'] +
            results['s3_buckets'] +
            results['iam_policies'] +
            results['unused_credentials'] +
            results['ssl_certificates']
        )
        
        results['summary'] = {
            'total_findings': len(all_findings),
            'critical': len([f for f in all_findings if f.get('severity') == 'CRITICAL']),
            'high': len([f for f in all_findings if f.get('severity') == 'HIGH']),
            'medium': len([f for f in all_findings if f.get('severity') == 'MEDIUM']),
            'low': len([f for f in all_findings if f.get('severity') == 'LOW']),
            'by_type': {}
        }
        
        for finding in all_findings:
            finding_type = finding.get('type', 'Unknown')
            results['summary']['by_type'][finding_type] = results['summary']['by_type'].get(finding_type, 0) + 1
        
        return results
    
    def get_ai_recommendations(self, findings: List[Dict[str, Any]]) -> Optional[str]:
        """Get AI-powered security hardening recommendations."""
        if not self.openai_client or not findings:
            return None
        
        # Prepare summary for AI
        findings_summary = json.dumps(findings[:20], indent=2, default=str)  # Limit to top 20 findings
        
        system_prompt = """You are an AWS security expert. Analyze the security findings and provide:

1. **Executive Summary**: Brief overview of the security posture
2. **Critical Actions**: Immediate steps to address critical/high severity issues
3. **Unnecessary Rules Analysis**: Identify security group rules that appear non-essential:
   - Rules with overly broad CIDR ranges (0.0.0.0/0) for non-web ports
   - Wide port ranges that should be narrowed
   - Duplicate or overlapping rules
   - Rules that could be replaced with more restrictive alternatives
   - Outbound rules that are overly permissive
4. **Prioritized Remediation Plan**: Ordered list of fixes by impact
5. **Best Practices**: General security hardening recommendations including:
   - Principle of least privilege for security groups
   - Using security group references instead of CIDR blocks where possible
   - Implementing VPN/bastion hosts for administrative access
6. **Compliance Implications**: Relevant compliance framework concerns (SOC2, HIPAA, PCI-DSS if applicable)

For each finding, explain:
- Why it's a risk
- What specific ports/protocols are problematic
- Whether the rule is likely essential or could be tightened/removed
- Concrete steps to remediate

Format your response in clear Markdown with headers and bullet points.
Be specific and actionable in your recommendations."""

        try:
            response = self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze these AWS security findings:\n\n{findings_summary}"}
                ],
                max_tokens=2500,
                temperature=0.3
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating AI recommendations: {str(e)}"
    
    def get_security_score(self, findings: List[Dict[str, Any]]) -> int:
        """Calculate a security score from 0-100 based on findings."""
        if not findings:
            return 100
        
        # Weight by severity
        severity_weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 5,
            'LOW': 2
        }
        
        total_deduction = 0
        for finding in findings:
            severity = finding.get('severity', 'LOW')
            total_deduction += severity_weights.get(severity, 1)
        
        score = max(0, 100 - total_deduction)
        return score
