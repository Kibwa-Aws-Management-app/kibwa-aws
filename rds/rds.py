import boto3
from rds.models import RdsEnum


class Rdsboto3:
    def __init__(self, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION):
        self.rds_client = boto3.client(
            'rds',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION
        )
        self.rds_db_subnet_group_name = 'test-subg'  # RDS DB Subnet Group 이름 설정
        self.rds_db_instance_identifier = 'aws-db'  # RDS DB 인스턴스 식별자 설정

    # RDS 서브넷 가용 영역 관리 체크
    def rds_check_rds_subnet_availability(self):
        response = self.rds_client.describe_db_subnet_groups(DBSubnetGroupName=self.rds_db_subnet_group_name)
        subnets = response['DBSubnetGroups'][0].get('Subnets', [])  # 'Subnets' 키를 먼저 확인하고, 없는 경우 빈 리스트 반환
        availability_zones = set(
            subnet.get('AvailabilityZone', '') for subnet in subnets)  # 'AvailabilityZone' 키를 먼저 확인하고, 없는 경우 빈 문자열 반환

        if len(availability_zones) == len(subnets):
            return {"status": True, "info": "RDS 서브넷 그룹 내 불필요한 가용 영역이 존재하지 않습니다."}
        else:
            return {"status": False, "info": "RDS 서브넷 그룹 내 불필요한 가용 영역이 존재합니다."}

    # RDS 암호화 설정 체크
    def rds_check_rds_encryption(self):
        response = self.rds_client.describe_db_instances(DBInstanceIdentifier=self.rds_db_instance_identifier)
        encryption_at_rest = response['DBInstances'][0]['StorageEncrypted']

        if encryption_at_rest:
            return {"status": True, "info": "RDS 데이터베이스 암호화가 활성화되어 있습니다."}
        else:
            return {"status": False, "info": "RDS 데이터베이스 암호화가 비활성화되어 있습니다."}

    # RDS 로깅 설정 체크
    def rds_check_rds_logging(self):
        response = self.rds_client.describe_db_log_files(DBInstanceIdentifier=self.rds_db_instance_identifier)
        log_files = response['DescribeDBLogFiles']

        if log_files:
            return {"status": True, "info": "CloudWatch 로그 스트림으로 보관하고 있습니다."}
        else:
            return {"status": False, "info": "CloudWatch 로그 스트림으로 보관하고 있지 않습니다."}

    # RDS Public Access 설정 체크
    def rds_check_rds_public_access(self):
        response = self.rds_client.describe_db_instances(DBInstanceIdentifier=self.rds_db_instance_identifier)
        db_instance = response['DBInstances'][0]
        publicly_accessible = db_instance['PubliclyAccessible']

        if publicly_accessible:
            return {"status": False, "info": "RDS에 대해 Public Access가 허용되어 있습니다."}
        else:
            return {"status": True, "info": "RDS에 대해 Public Access가 허용되어 있지 않습니다."}

    # DB 생성 삭제 권한 설정 체크
    def rds_check_db_creation_deletion_privileges(self):
        response = self.rds_client.describe_db_instances(DBInstanceIdentifier=self.rds_db_instance_identifier)
        db_instances = response['DBInstances']
        ec2_security_group_names = set()

        for db_instance in db_instances:
            for ec2_security_group in db_instance.get('VpcSecurityGroups', []):
                ec2_security_group_names.add(ec2_security_group['VpcSecurityGroupId'])

        if 'your_db_creation_deletion_security_group' in ec2_security_group_names:
            return {"status": False, "info": "DBE 이외의 사람이 데이터베이스 생성/삭제를 할 수 있도록 설정되어 있습니다."}
        else:
            return {"status": True, "info": "DBE만 데이터베이스 생성/삭제를 할 수 있도록 설정되어 있습니다."}


def rds_boto3(key_id, secret, region):
    rds_instance = Rdsboto3(key_id, secret, region)  # 클래스의 인스턴스 생성

    check_list = get_check_list()
    result = []

    for method in check_list:
        if hasattr(rds_instance, method):
            try:
                m = getattr(rds_instance, method)
                if callable(m):
                    buf = m()
                    buf['check_name'] = method[4:].upper()
                    result.append(buf)
                else:
                    result.append({"check_name": None, "status": False, "info": "체크 함수를 실행시키는 과정에서 문제가 발생하였습니다."})
            except Exception as e:
                print("error", e)
                result.append({"check_name": None, "status": False, "info": "체크 함수를 실행시키는 과정에서 문제가 발생하였습니다."})
        else:
            result.append({"check_name": None, "status": False, "info": "AWS 연결에 문제가 발생하였습니다. 액세스 아이디와 키를 재설정 해주세요."})

    return result


def get_check_list():
    return [
        'rds_check_rds_subnet_availability',
        'rds_check_rds_encryption',
        'rds_check_rds_logging',
        'rds_check_rds_public_access',
        'rds_check_db_creation_deletion_privileges',
    ]
