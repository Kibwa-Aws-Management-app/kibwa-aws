import boto3

from config import vpc_ep_id
from config import vpcId

class vpc:
    def __init__(self, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION):
        # EC2
        self.ec2_client = boto3.client(
            'ec2',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION
        )
        self.vpcs = self.ec2_client.describe_vpcs()['Vpcs']

        self.endpoint = self.ec2_client.describe_vpc_endpoints()['VpcEndpoints']
        self.endpoint_id = {vpc_ep_id}

        # STS
        self.sts_client = boto3.client(
            'sts',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION
        )
        self.account_arn = self.sts_client.get_caller_identity()['Arn']

        # ELBV2
        self.elbv2 = boto3.client(
            'elbv2',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION
        )

    # VPC Flow Log 설정
    # VPC Flow Log를 설정하지 않은 경우 Fail, VPC Flow Log를 설정한 경우 Pass
    def vpc_check_flow_logs(self):
        results = []
        
        for vpc in self.vpcs:
            vpc_id = vpcId
            vpc_flow_logs = self.ec2_client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])
            
            if len(vpc_flow_logs['FlowLogs']) == 0:
                results.append(vpc_id)
            else:
                print(f"[PASS]: VPC 계정 '{vpc_id}'에 VPC Flow Logs가 설정되어 있습니다.")

        if not results:
            print("[PASS] : VPC Flow Log를 설정함")
            return {"status": True, "info": "VPC 계정이 VPC Flow Logs가 설정되어 있습니다."}
        else:
            print(f"[FAIL]: VPC 계정 '{vpc_id}'에 VPC Flow Logs가 설정되어 있지 않습니다.")
        
            return {"status": False, "info": f"VPC 계정 '{vpc_id}'에 VPC Flow Logs가 설정되어 있지 않습니다."}



    # Endpoint
    # VPC endpoint가 모든 권한일 경우 Fail
    def vpc_check_endpoint_permissions(self):
        results = []
        endpoint_ids = self.endpoint_id

        for endpoint_id in endpoint_ids:

            vpc_endpoint = self.ec2_client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
            endpoint = vpc_endpoint['VpcEndpoints'][0]
            if "*" in endpoint['PolicyDocument']:
                results.append(endpoint_id)
            else:
                print("[PASS]:VPC Endpoint가 적절한 권한으로 설정되어 있습니다.")
        if not results:
            print("[PASS] : VPC Endpoint가 적절한 권한으로 설정되어 있습니다.")
            return {"status": True, "info": "VPC Endpoint가 적절한 권한으로 설정되어 있습니다."}
        else:
            print(f"[FAIL] : VPC Endpoint 계정 {results}: VPC Endpoint가 모든 권한으로 설정되어 있습니다.")
            
            return {"status": False, "info": f"VPC Endpoint 계정 {results}: VPC Endpoint가 모든 권한으로 설정되어 있습니다."}

    #  VPC endpoint 신뢰할 수 있는 계정일 경우 Pass, VPC endpoint 신뢰할 수 없는 계정일 경우 Fail
    # arn 사용
    def vpc_check_endpoint_trusted_account_with_arn(self):
        results = []
        endpoint_ids = self.endpoint_id
        vpc_ids = {vpcId}
        trusted_account_arn = self.account_arn

        for vpc_id in vpc_ids:
            for endpoint_id in endpoint_ids:
                vpc_endpoint = self.ec2_client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
                endpoint = vpc_endpoint['VpcEndpoints'][0]

                # 신뢰할 수 있는 arn인지 확인
                if isinstance(endpoint['PolicyDocument'], dict) and "Statement" in endpoint['PolicyDocument']:
                    statements = endpoint['PolicyDocument']['Statement']

                    for statement in statements:
                        if (
                            "Effect" in statement and statement["Effect"] == "Allow" and
                            "Principal" in statement and "AWS" in statement["Principal"] and
                            statement["Principal"]["AWS"] == trusted_account_arn
                        ):
                            print(f"[PASS]: VPC 계정 '{vpc_id}':  VPC endpoint 신뢰할 수 있는 계정")
                        else:
                            results.append(endpoint_id)        
        if not results:
            print("[PASS] : VPC endpoint 신뢰할 수 있는 계정")
            return {"status": True,"info": f"신뢰할 수 있는 계정입니다."}
        else:
            print(f"[FAIL]: VPC Endpoint 계정 {results}: 신뢰할 수 없는 계정입니다.")
            return {"status": False,"info": f"VPC Endpoint 계정 {results}: 신뢰할 수 없는 계정입니다."}

    # VPC endpoint 계정 2 개 중 모두 신뢰할 수 있는 계정일 경우 Pass, VPC endpoint 계정 2개 중 한 개만 신뢰할 수 있는 계정일 경우 Fail
    def vpc_check_endpoint_with_two_account_ids_one_trusted_one_not(self):
        results = []
        endpoint_ids = self.endpoint_id
        vpc_ids = {vpcId}
        trusted_account_ids = self.sts_client.get_caller_identity()['Account']

        for vpc_id in vpc_ids:
            for endpoint_id in endpoint_ids:
                response = self.ec2_client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])
                endpoint = response['VpcEndpoints'][0]

                if "PolicyDocument" in endpoint:
                    policy_document = endpoint['PolicyDocument']
                    trusted_count = 0

                    if isinstance(policy_document, str):
                        # Parse the string into a dictionary
                        import json
                        try:
                            policy_document = json.loads(policy_document)
                        except json.JSONDecodeError:
                            print(f"Failed to parse PolicyDocument for endpoint {endpoint_id}")
                            continue

                    if "Statement" in policy_document:
                        statements = policy_document.get('Statement', [])

                        for statement in statements:
                            if (
                                "Effect" in statement and statement["Effect"] == "Allow" and
                                "Principal" in statement and "AWS" in statement["Principal"]
                            ):
                                principal_aws = statement["Principal"]["AWS"]

                                if isinstance(principal_aws, list):
                                    for account_id in principal_aws:
                                        if account_id in trusted_account_ids:
                                            trusted_count += 1
                                elif isinstance(principal_aws, str):
                                    if principal_aws in trusted_account_ids:
                                        trusted_count += 1
                            else:
                                print("[FAIL] : 조건에 부합하지 않습니다.")

                    if trusted_count >= 2:
                        print("[PASS] : 2개 중 모두 신뢰할 수 있는 계정임.")
                    else:
                        results.append(vpc_id)

        if not results:
            print("[PASS] : 2개 중 모두 신뢰할 수 있는 계정입니다.")
            return {"status": True, "info": "모두 신뢰할 수 있는 계정입니다."}
        else:
            print(f"[FAIL] : VPC Endpoint 계정 {results}: 신뢰할 수 없는 계정입니다.")
            return {"status": False, "info": f"VPC Endpoint 계정 {results}: 신뢰할 수 없는 계정입니다."}

    # 라우팅 테이블 페어링
    # VPC와 라우팅 테이블이 잘 페어링되어 있지 않은 경우 Fail, VPC와 라우팅 테이블이 잘 페어링되어 있는 경우  Pass
    def vpc_check_routing_table_peering(self):
        results = []
        results2 = []
        vpc_ids = {vpcId}

        for vpc_id in vpc_ids:
            try:
                response = self.ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                routing_tables = response['RouteTables']

                if routing_tables:
                    # 라우팅 테이블이 존재하는지 확인하고, VPC 페어링 상태 확인
                    routing_table = routing_tables[0]
                    vpc_peering_state = routing_table.get('VpcPeeringConnections', [])
                    if vpc_peering_state:
                        print("Pass - VPC and Routing Table are properly peered.")
                    else:
                        results.append(vpc_id)
                else:
                    results2.append(vpc_id)
            except Exception as e:
                print(f"에러: {e}")
        if not results and not results2:
            print("[PASS] : 2개 중 모두 신뢰할 수 있는 계정임")
            return {"status": True, "info": f"VPC 계정 모두 Routing Table이 페어링되어 있습니다."}
        if not results2:
            print(f"[FAIL] : VPC 계정 {results}: Routing Table이 페어링되어 있지 않습니다.")
            return {"status": False, "info": f"VPC 계정 {results}: Routing Table이 페어링되어 있지 않습니다."}
        else:
            print(f"[FAIL] : VPC 계정 {results2}: Routing Table이 페어링되어 있지 않습니다.")
            return {"status": False, "info": f"VPC 계정 {results2}: Routing Table를 찾을 수 없습니다."}

    # 서브넷
    # VPC 서브넷이 없을 경우 Fail
    def vpc_check_subnets(self):
        results = []
        vpc_ids = {vpcId}
        
        for vpc_id in vpc_ids:
            try:
                response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
                subnets = response['Subnets']

                if subnets:
                    print("[PASS] : 서브넷이 존재합니다.")
                else:
                    results.append(vpc_id)
            except Exception as e:
                print(f"에러: {e}")
                # 에러 처리를 추가하거나 로깅을 통해 디버깅할 수 있습니다.

        if not results:
            print("[PASS] : 서브넷이 존재합니다.")
            return {"status": True, "info": "VPC 계정에 서브넷이 존재합니다."}
        else:
            print(f"[FAIL] : VPC 계정 {results}: 서브넷이 존재하지 않습니다.")
            return {"status": False, "info": f"VPC 계정 {results}: 서브넷이 존재하지 않습니다."}


    # VPC 서브넷 다른 가용 영역(az)일 경우 Pass, VPC 서브넷 같은 가용 영역(az)일 경우 Fail
    def vpc_check_subnet_availability_zone(self):
        results = []
        vpc_ids = {vpcId}

        for vpc_id in vpc_ids:
            response = self.ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])

            if response['Subnets']:
                for subnet in response['Subnets']:
                    subnet_id = subnet['SubnetId']  # 각 서브넷의 ID를 가져옴

                    # 서브넷에 대한 정보를 가져오도록 수정
                    subnet_res = self.ec2_client.describe_subnets(SubnetIds=[subnet_id])
                    subnet_availability_zone = subnet_res['Subnets'][0]['AvailabilityZone']

                    # VPC에 대한 정보가 아닌 서브넷에 대한 정보를 가져오도록 수정
                    vpc_id = subnet_res['Subnets'][0]['VpcId']
                    vpc_res = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
                    vpc_availability_zone = subnet_availability_zone  # 서브넷과 동일한 Availability Zone 사용

                    if subnet_availability_zone == vpc_availability_zone:
                        print("[PASS] : 다른 가용 영역(AZ)입니다")
                    else:
                        results.append(subnet_id)
            else:
                print("No subnets found for the given VPC.")

        if not results:
            print("[PASS] : 다른 가용 영역(AZ)입니다")
            return {"status": True, "info": f"서브넷과 다른 가용 영역(AZ)입니다."}
        else:
            print(f"[FAIL] : VPC 계정 {vpc_id}, Subnet {subnet_id}: 같은 가용 영역(AZ)입니다.")
            return {"status": False, "info": f"VPC 계정 {vpc_id}, Subnet {subnet_id}: 같은 가용 영역(AZ)입니다."}

    # elbv2
    # elbv2 로깅을 사용하도록 설정하지 않은 경우 Fail, elbv2 로깅을 사용하도록 설정한 경우 Pass
    def elbv2_check_logging_enabled(self):
        results = []

        response = self.elbv2.describe_load_balancers()
        elb_logging_disabled_count = 0

        for elb in response['LoadBalancers']:
            load_balancer_name = elb['LoadBalancerName']
            attributes = self.elbv2.describe_load_balancer_attributes(
                LoadBalancerName=load_balancer_name)
            for attr in attributes['Attributes']:
                if attr['Key'] == 'access_logs.s3.enabled' and attr['Value'] == 'false':
                    elb_logging_disabled_count += 1

        if elb_logging_disabled_count > 0:
            print("[PASS] : ELBv2 load balancer(s)가 로깅을 사용하고 있습니다.")
        else:
            results.append(elb_logging_disabled_count)
        if not results:
            print("[PASS] : ELBv2 load balancer(s)가 로깅을 사용하고 있습니다.")
            return {"status": True, "info": "ELBv2 load balancer(s)가 로깅을 사용하고 있습니다."}
        else:
            print(f"[FAIL] : {results} ELBv2 load balancer(s)가 로깅을 사용하고 있지 않습니다.")
            return {"status": False, "info": f" {results} ELBv2 load balancer(s)가 로깅을 사용하고 있지 않습니다."}


def vpc_boto3(key_id, secret, region):
    vpc_instance = vpc(key_id, secret, region)  # 클래스의 인스턴스 생성

    check_list = get_check_list()
    result = []

    for method in check_list:
        if hasattr(vpc_instance, method):
            m = getattr(vpc_instance, method)
            if callable(m):
                buf = m()
                buf['check_name'] = method.upper()
                # buf['check_name'] = str(method)
                result.append(buf)
            else:
                result.append({"check_name": None, "status": False, "info": "체크 함수를 실행시키는 과정에서 문제가 발생하였습니다."})
        else:
            result.append(
                {"check_name": None, "status": False, "info": "AWS 연결에 문제가 발생하였습니다. 액세스 아이디와 키를 재설정 해주세요."})

    return result


def get_check_list():
    return [
        'vpc_check_flow_logs'
        'vpc_check_endpoint_permissions'
        'vpc_check_endpoint_trusted_account_with_arn'
        'vpc_check_endpoint_with_two_account_ids_one_trusted_one_not'
        'vpc_check_routing_table_peering'
        'vpc_check_subnets'
        'vpc_check_subnet_availability_zone'
        'elbv2_check_logging_enabled'
    ]

    
