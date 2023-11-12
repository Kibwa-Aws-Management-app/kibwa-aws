import boto3
from datetime import datetime, timedelta, timezone
import shodan

class ec2:
    def __init__(self, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION):
        self.ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION
        )
        self.instance_age_limit = 180 #원하는데로 변경
        self.ssm_client = boto3.client('ssm')

    #은경 ######################
    def ec2_instance_managed_by_ssm(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        results = []
        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                iam_profile = instance.get('IamInstanceProfile', {}).get('Arn', '')
                ssm_managed = self.is_instance_managed_by_ssm(instance_id, iam_profile)
                
                if ssm_managed:
                    print(f"Instance {instance_id}: PASS - Managed by Systems Manager.")
                else:
                    print(f"Instance {instance_id}: FAIL - Not managed by Systems Manager.")
                    results.append(instance_id)
        if not results:
            print("[PASS] : Instance managed by Systems Manager.")
            return {"status": True, "info": "모든 인스턴스가 ssm에 관리되고 있어 안전합니다."}
        return {"status": False, "info": f"'{results}'인스턴스가 ssm에 관리되고 있지 않습니다."}
    
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
        
    def ec2_instance_older_than_specific_days(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        results = []
        current_time = datetime.now(timezone.utc)

        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                launch_time = instance['LaunchTime']

                age_limit = current_time - timedelta(days=self.instance_age_limit)

                if launch_time < age_limit:
                   print(f"[FAIL] : EC2 Instance {instance_id} is older than {self.instance_age_limit} days.")
                   results.append(instance_id)
                else:
                    print(f"[PASS] : EC2 Instance {instance_id} is not older than {self.instance_age_limit} days.")

        if not results:
            print("[PASS] : Instance managed by Systems Manager.")
            return {"status": True, "info": "모든 인스턴스가 ssm에 관리되고 있어 안전합니다."}
        return {"status": False, "info": f"'{results}'인스턴스가 ssm에 관리되고 있지 않습니다."}

    def ec2_instance_profile_attached(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        results = []

        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                has_instance_profile = bool(instance.get('IamInstanceProfile', {}))
                if has_instance_profile:
                    print(f"[PASS] : EC2 Instance {instance_id} is connected to an IAM Instance Profile.")
                else:
                    print(f"[FAIL] : EC2 Instance {instance_id} is not connected to an IAM Instance Profile.")
                    results.append(instance_id)
        if not results:
            print("[PASS] : Instance is connected to an IAM Instance Profile.")
            return {"status": True, "info": "모든 인스턴스가 인스턴스 프로파일과 연결되어 안전합니다."}
        return {"status": False, "info": f"'{results}'인스턴스가 ssm에 인스턴스 프로파일과 연결되어 있지 않습니다."}

    def ec2_instance_public_ip(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        results = []

        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                has_public_ip = 'PublicIpAddress' in instance
                if has_public_ip:
                    print(f"[PASS] : EC2 Instance {instance_id} has public IP")
                else:
                    print(f"[FAIL] : EC2 Instance {instance_id} has not public IP")
                    results.append(instance_id)

        if not results:
            print("[PASS] : Instance has public IP")
            return {"status": True, "info": "모든 인스턴스가 퍼블릭 IP를 보유하고 있어 안전합니다."}
        return {"status": False, "info": f"'{results}'인스턴스가 퍼블릭 IP를 보유하고 있지 않습니다."}
    
    def ec2_instance_secrets_user_data(self):
        ec2_instances = self.ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        sensitive_keywords = ["password", "secret", "private_key", "api_key"]  # 민감한 정보 키워드
        results = []

        for reservation in ec2_instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                user_data = instance.get('UserData', '')
                
                # 사용자 데이터에 민감한 키워드가 있는지 검사
                for keyword in sensitive_keywords:
                    if keyword in user_data:
                        print(f"[FAIL] : EC2 Instance {instance_id} contains sensitive information in user data.")
                        results.append(instance_id)
                        break  # 민감한 정보가 하나라도 발견되면 검사 중단
                else:
                    print(f"[PASS] : EC2 Instance {instance_id} does not contain sensitive information in user data.")

        if not results:
            print("[PASS] : No instances contain sensitive information in user data.")
            return {"status": True, "info": "모든 인스턴스의 사용자 데이터에 민감한 정보가 없습니다."}
        else:
            return {"status": False, "info": f"'{results}' 인스턴스의 사용자 데이터에 민감한 정보가 포함되어 있습니다."}


    #은솔 
    #########################################
    '''def ec2_elastic_ip_shodan(shodan_api_key, elastic_ip):
        try:
            # Shodan API 초기화
            shodan_api = shodan.Shodan(shodan_api_key)

            # Shodan에서 Elastic IP 주소 확인
            check = shodan_api.host(elastic_ip)

            # Elastic IP 주소가 Shodan에 확인되면 FAIL
            result = "FAIL - Elastic IP address in Shodan."

        except shodan.APIERROR as e:
            if e.value == "No information available for that IP.":
                # Elastic IP 주소가 Shodan에 확인되지 않으면 PASS
                print("PASS - Elastic IP address not in Shodan.")
                return {"status": True, "info": "Elastic IP 주소가 Shodan에 확인되지 않아 안전합니다."}
            else:
                # 다른 오류 처리
                print(str(e))
                return {"status": False, "info": "Elastic IP 주소가 Shodan에 등록되어 있습니다."}
            
        print(f"Check Elastic IP address in Shodan : {result}")


    # Elastic IP 주소 할당 확인
    def ec2_elastic_ip_unassgined(ec2, elastic_ip):
        try:
            response = ec2.describe_addresses(PublicIps=[elastic_ip])
            if response['Addresses']:
                # Elastic IP 주소가 할당되면 PASS
                result = "PASS"
                return {"status": True, "info": "Elastic IP 주소가 할당되어 있어 안전합니다."}
            else:
                # Elastic IP 주소가 할당되지 않으면 FAIL
                result = "FAIL"
                return {"status": False, "info": "Elastic IP 주소가 할당되어 있지 않습니다."}
        except Exception as e:
            result = str(e)

        print(f"Elastic IP address assignment: {result}")
    

    # EC2 인스턴스 상세 모니터링 확인
    def ec2_instance_detailed_monitoring_enabled(ec2, instance_id):
        try:
            response = ec2.describe_instance_attribute(
                InstanceId=instance_id, Attribute='instanceMonitoring')
            if response['InstanceMonitoring']['State'] == 'enabled':
                # 상세 모니터링이 활성화되면 PASS
                result = "PASS - EC2 instance detailed monitoring enabled."
                return {"status": True, "info": "상세 모니터링이 활성화되어 있어 안전합니다."}
            else:
                # 상세 모니터링이 비활성화되면 FAIL
                result = "FAIL - EC2 instance detailed monitoring not enabled."
                return {"status": False, "info": "상세 모니터링이 비활성화 상태입니다."}
        except Exception as e:
            result = str(e)

        print(f"Check EC2 instance detailed monitoring: {result}")


    # EC2 인스턴스 IMDSv2 확인
    def ec2_instance_imdsv2_enabled(ec2, instance_id):
        try:
            response = ec2.describe_instance_attribute(
                InstanceId=instance_id, Attribute='sriovNetSupport')
            if response['SriovNetSupport']['Value'] == 'simple':
                # IMDSv2가 활성화되면 PASS
                result = "PASS - EC2 instance IMDSv2 enabled."
                return {"status": True, "info": "IMDSv2가 활성화되어있어 안전합니다."}
            else:
                # IMDSv2가 비활성화되면 FAIL
                result = "FAIL - EC2 instance IMDSv2 not enabled."
                return {"status": False, "info": "IMDSv2가 활성화되어 있지 않습니다."}
        except Exception as e:
            result = str(e)

        print(f"Check EC2 instance IMDSv2: {result}")


    # EC2 인스턴스의 인터넷 통신 가능여부와 프로파일 설정 여부 확인
    def ec2_instance_internet_facing_with_instance_profile(ec2, instance_id):
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            internet_accessible = instance['SourceDestCheck']
            iam_profile = instance.get('IamInstanceProfile', None)

            if internet_accessible and iam_profile:
                # 인터넷 통신 가능하고 프로파일이 설정되면 PASS
                result = "PASS"
                return {"status": True, "info": " 인터넷 통신 가능하고 프로파일이 설정되어있어 안전합니다."}
            else:
                # 하나라도 설정 안되었으면 FAIL
                result = "FAIL"
                return {"status": False, "info": " 인터넷 통신 가능, 프로파일이 설정 조건을 충족하지 않습니다."}
        except Exception as e:
            result = str(e)

        print(f"Check EC2 instance internet and profile: {result}")

    def get_user_info(self, user_name):
        info = self.ec2_client.get_user(UserName=user_name)
        print(info)'''

    #지연 ###########################3
    def ec2_ami_public(self):
        # AMI의 공개 여부 확인
        ami_images = self.ec2_client.describe_images(Owners=['self'])
        results = []

        for image in ami_images['Images']:
            image_id = image['ImageId']
            is_public = image['Public']
            status = 'FAIL' if is_public else 'PASS'
            print(f"[{status}] AMI {image_id} - AMI is {'public' if is_public else 'not public'}")
            if status == 'FAIL':
                results.append(image_id)
        if results:
            return {"status": False, "info": f"'{results}' AMI가 공개되어 있습니다."}
        else:
            return {"status": True, "info": "모든 AMI가 비공개 상태입니다."}

    def ec2_ebs_snapshots_encrypted(self):
        # 스냅샷 암호화 상태 확인
        snapshots = self.ec2_client.describe_snapshots(OwnerIds=['self'])
        results = []
        for snapshot in snapshots['Snapshots']:
            snapshot_id = snapshot['SnapshotId']
            is_encrypted = snapshot['Encrypted']
            status = 'PASS' if is_encrypted else 'FAIL'
            print(f"[{status}] Snapshot {snapshot_id} - Snapshot is {'encrypted' if is_encrypted else 'not encrypted'}")
            if status == 'FAIL':
                results.append(snapshot_id)
        if results:
            return {"status": False, "info": f"'{results}' 스냅샷이 암호화되어 있지 않습니다."}
        else:
            return {"status": True, "info": "모든 스냅샷이 암호화되어 있습니다."}

        
    def ec2_ebs_public_snapshot(self):
        snapshots = self.ec2_client.describe_snapshots(OwnerIds=['self'])['Snapshots']
        
        results = []

        for snapshot in snapshots:
            # 'Public' 키의 존재 여부를 확인하고 처리
            if 'Public' in snapshot:
                is_public = snapshot['Public']
                if is_public:
                    print(f"[FAIL] : Snapshot {snapshot['SnapshotId']} is public.")
                    results.append(snapshot['SnapshotId'])
                else:
                    print(f"[PASS] : Snapshot {snapshot['SnapshotId']} is not public.")
            else:
                # 'Public' 키가 없을 경우
                print(f"[PASS] : Snapshot {snapshot['SnapshotId']} does not have 'Public' key.")

        if not results:
            print("[PASS] : No public snapshots found.")
            print(results)
            return {"status": True, "info": "모든 스냅샷이 비공개 상태입니다."}
        else:
            return {"status": False, "info": f"{results} 스냅샷이 공개 상태입니다."}
    
        
    def ec2_ebs_default_encryption(self):
        # 기본 볼륨 암호화 상태 확인
        volumes = self.ec2_client.describe_volumes()
        results = []
        for volume in volumes['Volumes']:
            volume_id = volume['VolumeId']
            is_encrypted = volume['Encrypted']
            status = 'PASS' if is_encrypted else 'FAIL'
            print(f"[{status}] Volume {volume_id} - Volume is {'encrypted' if is_encrypted else 'not encrypted'}")
            if status == 'FAIL':
                results.append(volume_id)
        if results:
            return {"status": False, "info": f"'{results}' 볼륨이 암호화되어 있지 않습니다."}
        else:
            return {"status": True, "info": "모든 볼륨이 암호화되어 있습니다."}

        
    def ec2_ebs_volume_encryption(self):
        # 볼륨 암호화 상태 확인
        volumes = self.ec2_client.describe_volumes()
        results = []
        for volume in volumes['Volumes']:
            volume_id = volume['VolumeId']
            is_encrypted = volume['Encrypted']
            status = 'PASS' if is_encrypted else 'FAIL'
            print(f"[{status}] Volume {volume_id} - Volume is {'encrypted' if is_encrypted else 'not encrypted'}")
            if status == 'FAIL':
                results.append(volume_id)
        if results:
            return {"status": False, "info": f"'{results}' 볼륨이 암호화되어 있지 않습니다."}
        else:
            return {"status": True, "info": "모든 볼륨이 암호화되어 있습니다."}

    
def ec2_boto3(key_id, secret, region):
    ec2_instance = ec2(key_id, secret, region)  # 클래스의 인스턴스 생성
    print(ec2_instance.ec2_instance_managed_by_ssm())
    ec2_instance.ec2_instance_managed_by_ssm()
    print(ec2_instance.ec2_instance_older_than_specific_days())
    check_list = get_check_list()
    result = []

    for method in check_list:
        if hasattr(ec2_instance, method):
            m = getattr(ec2_instance, method)
            if callable(m):
                buf = m()
                buf['check_name'] = method[4:].upper()
                result.append(buf)
            else:
                result.append({"check_name": None, "status": False, "info": "체크 함수를 실행시키는 과정에서 문제가 발생하였습니다."})
        else:
            result.append({"check_name": None, "status": False, "info": "AWS 연결에 문제가 발생하였습니다. 액세스 아이디와 키를 재설정 해주세요."})
    print("result")
    return result



def get_check_list():
    return [
        'ec2_instance_managed_by_ssm',
        'ec2_instance_older_than_specific_days',
        'ec2_instance_profile_attached',
        'ec2_instance_public_ip',
        'ec2_instance_secrets_user_data',
        #'ec2_elastic_ip_shodan',
        #'ec2_elastic_ip_unassgined',
        #'ec2_instance_detailed_monitoring_enabled',
        #'ec2_instance_imdsv2_enabled',
        #'ec2_instance_internet_facing_with_instance_profile'
        'ec2_ami_public',
        'ec2_ebs_snapshots_encrypted',
        'ec2_ebs_public_snapshot',
        'ec2_ebs_default_encryption',
        'ec2_ebs_volume_encryption'
    ]
