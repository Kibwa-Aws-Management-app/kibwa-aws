import boto3

class vpc:
    def __init__(self, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION):
            # EC2
            self.ec2_client = boto3.client(
                'ec2',
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                region_name=AWS_DEFAULT_REGION
            )
            self.vpcs=self.ec2_client.describe_vpcs()['Vpcs']

            self.endpoint = self.ec2_client.describe_vpc_endpoints()['VpcEndpoints']
            self.endpoint_id = self.endpoint['VpcEndpointId']

            # STS
            self.sts_client = boto3.client(
                'sts',
                aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                region_name=AWS_DEFAULT_REGION
            )
            self.account_arn=self.sts_client.get_caller_identity()['Arn']

            # ELBV2
            self.elbv2 = boto3.client(
                'elbv2',
                 aws_access_key_id=AWS_ACCESS_KEY_ID,
                aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                region_name=AWS_DEFAULT_REGION
                  )
            



    # VPC Flow Log 설정
    # VPC Flow Log를 설정하지 않은 경우 Fail, VPC Flow Log를 설정한 경우 Pass
    def check_vpc_flow_logs(self):
        results=[]
        vpc_ids=self.vpcs['VpcId']
        for vpc_id in vpc_ids:
            vpc_fowlogs = self.ec2_client.describe_flow_logs(
                Filters=[{'Values': [vpc_id]}])
            if len(vpc_fowlogs['FlowLogs']) == 0:
                results.append({"status": False, "info": f"VPC 계정 {vpc_id}: VPC Flow Logs가 설정되어 있지 않습니다."})
            else:
                results.append({"status": True, "info": f"VPC 계정 {vpc_id}: VPC Flow Logs가 설정되어 있습니다."})
        return results
                

       


    # Endpoint
    # VPC endpoint가 모든 권한일 경우 Fail
    def check_vpc_endpoint_permissions(self):
        results=[]
        endpoint_ids=self.endpoint_id

        for endpoint_id in endpoint_ids:

            vpc_endpoint = self.ec2_client.describe_vpc_endpoints(endpoint_id)
            endpoint = vpc_endpoint['VpcEndpoints'][0]
            if "*" in endpoint['PolicyDocument']:
                results.append({"status": False, "info": f"VPC Endpoint 계정 {endpoint_id}: VPC Endpoint가 모든 권한으로 설정되어 있습니다."})
            else:
                results.append({"status": True, "info": f"VPC Endpoint 계정 {endpoint_id}: VPC Endpoint가 적절한 권한으로 설정되어 있습니다."})
        return results


    #  VPC endpoint 신뢰할 수 있는 계정일 경우 Pass, VPC endpoint 신뢰할 수 없는 계정일 경우 Fail
    # arn 사용
    def check_vpc_endpoint_trusted_account_with_arn(self):
        results=[]
        endpoint_ids=self.endpoint_id
        vpc_ids=self.vpcs['VpcId']
        trusted_account_arn=self.account_arn
        
        for vpc_id in vpc_ids:

            for endpoint_id in endpoint_ids:
                vpc_endpoint = self.ec2_client.describe_vpc_endpoints(endpoint_id)
                endpoint = vpc_endpoint['VpcEndpoints'][0]

                # 신뢰할 수 있는 arn인지 확인
                if "Statement" in endpoint['PolicyDocument']:
                    statements = endpoint['PolicyDocument']['Statement']
                    for statement in statements:
                        if (
                            "Effect" in statement and statement["Effect"] == "Allow" and
                            "Principal" in statement and "AWS" in statement["Principal"] and
                            statement["Principal"]["AWS"] == trusted_account_arn
                        ):
                            results.append({"status": True, "info": f"VPC 계정 {vpc_id} VPC Endpoint 계정 {endpoint_id}: 신뢰할 수 있는 계정입니다."})
                            
                        else:
                            results.append({"status": False, "info": f"VPC 계정 {vpc_id} VPC Endpoint 계정 {endpoint_id}: 신뢰할 수 없는 계정입니다."})


        return results


    # VPC endpoint 계정 2 개 중 모두 신뢰할 수 있는 계정일 경우 Pass, VPC endpoint 계정 2개 중 한 개만 신뢰할 수 있는 계정일 경우 Fail
    def check_vpc_endpoint_with_two_account_ids_one_trusted_one_not(self):
        
        results=[]
        endpoint_ids=self.endpoint_id
        vpc_ids=self.vpcs['VpcId']
        trusted_account_ids=self.sts_client.get_caller_identity()['Account']
        
        for vpc_id in vpc_ids:
            for endpoint_id in endpoint_ids:
                response = self.ec2_client.describe_vpc_endpoints(endpoint_id)
                endpoint = response['VpcEndpoints'][0]

                if "PolicyDocument" in endpoint:
                    policy_document = endpoint['PolicyDocument']
                    trusted_count = 0

                    if "Statement" in policy_document:
                        statements = policy_document['Statement']

                        for statement in statements:
                            if (
                                "Effect" in statement and statement["Effect"] == "Allow" and
                                "Principal" in statement and "AWS" in statement["Principal"]
                            ):
                                if isinstance(statement["Principal"]["AWS"], list):
                                    for account_id in statement["Principal"]["AWS"]:
                                        if account_id in trusted_account_ids:
                                            trusted_count += 1

                                elif isinstance(statement["Principal"]["AWS"], str):
                                    if statement["Principal"]["AWS"] in trusted_account_ids:
                                        trusted_count += 1
                            else:
                                print("조건에 부합하지 않습니다.")

                    if trusted_count >= 2:
                        results.append({"status": True, "info": f"VPC 계정 {vpc_id} VPC Endpoint 계정 {endpoint_id}: 신뢰할 수 있는 계정입니다."})
                        
                    else:
                        results.append({"status": False, "info": f"VPC 계정 {vpc_id} VPC Endpoint 계정 {endpoint_id}: 신뢰할 수 없는 계정입니다."})            

        return results


    # 라우팅 테이블 페어링
    # VPC와 라우팅 테이블이 잘 페어링되어 있지 않은 경우 Fail, VPC와 라우팅 테이블이 잘 페어링되어 있는 경우  Pass
    def check_vpc_routing_table_peering(self):
       results=[]
       vpc_ids=self.vpcs['VpcId']

       for vpc_id in vpc_ids:
        response = self.ec2_clinet.describe_route_tables(Filters=[{'Values': [vpc_id]}])

            # 라우팅 테이블이 존재하는지 확인하고, VPC 페어링 상태 확인
        if response['RouteTables']:
                routing_table = response['RouteTables'][0]
                vpc_peering_state = routing_table.get('VpcPeeringConnections', [])
                if vpc_peering_state:
                    results.append({"status": True, "info": f"VPC 계정 {vpc_id}: Routing Table이 페어링되어 있습니다."})
                    print("Pass - VPC and Routing Table are properly peered.")
                else:
                    results.append({"status": False, "info": f"VPC 계정 {vpc_id}: Routing Table이 페어링되어 있지 않습니다."})
                    
        else:
            results.append({"status": False, "info": f"VPC 계정 {vpc_id}: Routing Table를 찾을 수 없습니다."})
        
        return results

        

    

    # 서브넷
    # VPC 서브넷이 없을 경우 Fail
    def check_vpc_subnets(self):
        results=[]
        vpc_ids=self.vpcs['VpcId']
        for vpc_id in vpc_ids:
            response = self.ec2_client.describe_subnets(Filters=[{'Values': [vpc_id]}])
            subnets = response['Subnets']

            if subnets:
                results.append({"status": True, "info": f"VPC 계정 {vpc_id}: 서브넷이 존재합니다."})
                
            else:
                results.append({"status": False, "info": f"VPC 계정 {vpc_id}: 서브넷이 존재하지 않습니다."})
        
        return results


    # VPC 서브넷 다른 가용 영역(az)일 경우 Pass, VPC 서브넷 같은 가용 영역(az)일 경우 Fail
    def check_vpc_subnet_availability_zone(self):
        results=[]
        vpc_ids=self.vpcs['VpcId']
        for vpc_id in vpc_ids:

            response =self.ec2_client.describe_subnets(Filters=[{'Values': [vpc_id]}])

            if response['Subnets']:
                for subnet in response['Subnets']:
                    subnet_ids = subnet['SubnetId']            
            else:
                print("No subnets found for the given VPC.")

            for subnet_id in subnet_ids:
                subnet_res = self.ec2_client.describe_subnets(SubnetIds=[subnet_id])
                subnet_availability_zone = subnet_res['Subnets'][0]['AvailabilityZone']

                vpc = subnet_res['Subnets'][0]['VpcId']
                subnet_res = self.ec2_client.describe_vpcs(VpcIds=[vpc])
                vpc_availability_zone = subnet_res['Vpcs'][0]['AvailabilityZone']

                if subnet_availability_zone == vpc_availability_zone:
                    results.append({"status": False, "info": f"VPC 계정 {vpc_id}, Subnet {subnet_id}: 같은 가용 영역(AZ)입니다."})
                else:
                    results.append({"status": True, "info": f"VPC 계정 {vpc_id}, Subnet {subnet_id}: 다른 가용 영역(AZ)입니다."})
        return results



    # elbv2
    # elbv2 로깅을 사용하도록 설정하지 않은 경우 Fail, elbv2 로깅을 사용하도록 설정한 경우 Pass
    def check_elbv2_logging_enabled(self):
        results=[]

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
            results.append({"status": False, "info": f" {elb_logging_disabled_count} ELBv2 load balancer(s)가 로깅을 사용하고 있지 않습니다."})
            
        else:
            results.append({"status": True, "info": f" {elb_logging_disabled_count} ELBv2 load balancer(s)가 로깅을 사용하고 있습니다."})

        return results


    


    def get_check_list(self):
        return [
            'check_vpc_flow_logs',
            'check_vpc_endpoint_permissions',
            'check_vpc_endpoint_trusted_account_with_arn',
            'check_vpc_endpoint_with_two_account_ids_one_trusted_one_not',
            'check_vpc_routing_table_peering',
            'check_vpc_subnets',
            'check_vpc_subnet_availability_zone',
            'check_elbv2_logging_enabled'

    ]

    # print("VPC Flow Logs 설정:", check_vpc_flow_logs(vpc_id))
    # print("VPC Endpoint 권한:", check_vpc_endpoint_permissions(endpoint_id))
    # print("VPC Endpoint 신뢰할 수 있는 계정:",
    #     check_vpc_endpoint_trusted_account_with_arn(vpc_id, endpoint_id, trusted_account_arn))
    # print("VPC Endpoint 2개 계정 신뢰 확인:", vpc_endpoint_with_two_account_ids_one_trusted_one_not(
    #     vpc_id, endpoint_ids, trusted_account_ids))
    # print("VPC Routing:", check_vpc_routing_table_peering(vpc_id, routing_table_id))
    # print("VPC 서브넷:", check_vpc_subnets(vpc_id))
    # print("VPC 서브넷 가용 영역:", check_subnet_availability_zone(subnet_id))
    # print("ELBv2 로깅:", check_elbv2_logging_enabled())
