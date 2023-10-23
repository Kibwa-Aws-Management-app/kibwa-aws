import boto3
from datetime import datetime, timedelta, timezone

class ec2:
    def __init__(self):
        self.ec2_client = boto3.client('ec2')
        self.instance_age_limit = 180 #원하는데로 변경
        self.ssm_client = boto3.client('ssm')

    def check_instances_managed_by_ssm(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        
        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                iam_profile = instance.get('IamInstanceProfile', {}).get('Arn', '')
                ssm_managed = self.is_instance_managed_by_ssm(instance_id, iam_profile)
                
                if ssm_managed:
                    print(f"Instance {instance_id}: PASS - Managed by Systems Manager.")
                else:
                    print(f"Instance {instance_id}: FAIL - Not managed by Systems Manager.")

    def is_instance_managed_by_ssm(self, instance_id, iam_profile_arn):
        try:
            response = self.ssm_client.describe_instance_information(InstanceInformationFilterList=[{'key': 'InstanceIds', 'valueSet': [instance_id]}])
            if response.get('InstanceInformationList'):
                # Check if IAM profile and SSM role match
                ssm_role = response['InstanceInformationList'][0].get('IamRole')
                return ssm_role == iam_profile_arn
            return False
        except Exception as e:
            print(f"Error checking SSM management for instance {instance_id}: {str(e)}")
            return False
        
    def check_instance_age(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

        current_time = datetime.now(timezone.utc)

        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                launch_time = instance['LaunchTime']

                age_limit = current_time - timedelta(days=self.instance_age_limit)

                if launch_time < age_limit:
                    result = "FAIL"
                    reason = f"EC2 Instance {instance_id} is older than {self.instance_age_limit} days."
                else:
                    result = "PASS"
                    reason = f"EC2 Instance {instance_id} is not older than {self.instance_age_limit} days."

                print(f"{result}: {reason}")

    def check_instance_profile_attached(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                has_instance_profile = bool(instance.get('IamInstanceProfile', {}))
                status = 'FAIL' if has_instance_profile else 'PASS'
                print(f"EC2 Instance {instance_id}: {status}")

    def check_public_ip_addresses(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                has_public_ip = 'PublicIpAddress' in instance
                status = 'PASS' if not has_public_ip else 'FAIL'  
                print(f"EC2 Instance {instance_id}: {status}")

if __name__ == '__main__':
    ec2c = ec2()
    ec2c.check_instances_managed_by_ssm()
    print("-------")
    ec2c.check_instance_age()
    print("-------")
    ec2c.check_instance_profile_attached()
    print("-------")
    ec2c.check_public_ip_addresses()
    #print("-------")
    #ec2c.check_public_ip_addresses()
    #print("-------")
