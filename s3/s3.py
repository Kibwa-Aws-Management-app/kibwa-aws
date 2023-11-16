import boto3


class S3boto3:
    def __init__(self, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION):
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION
        )
        self.s3_buckets = self.s3_client.list_buckets()['Buckets']
        print("s3", self.s3_client)
        print("s3 bucket", self.s3_buckets)

    # S3가 계정에 대해 공개 액세스 차단이 있는지 확인

    # def check_s3_public_access_block(self):
    #
    #     for bucket in self.s3_buckets:
    #         bucket_name = bucket['Name']
    #         bucket_access = self.s3_client.get_public_access_block(Bucket=bucket_name)
    #         if self.no_s3_public_access_block(bucket_access):
    #             return {"status": True, "info": f"S3 버킷 {bucket_name}: 공개 액세스 차단이 활성화되어 있습니다."}
    #         else:
    #             return {"status": False, "info": f"S3 버킷 {bucket_name}: 공개 액세스 차단이 비활성화되어 있습니다."}
    #
    # def no_s3_public_access_block(self):
    #     bucket_block = self['PublicAccessBlockConfiguration']
    #
    #     for i in range(len(bucket_block)):
    #         # 'BlockPublicAcls' 'IgnorePublicAcls' 'BlockPublicPolicy' 'RestrictPublicBuckets'
    #         try:
    #             if (bucket_block[i]) == False:
    #                 print("[FAIL]", f"{bucket_block[i]}가 비활성화되어 있습니다.")
    #                 return {"status": False, "info": f"{bucket_block[i]}가 비활성화되어 있습니다."}
    #         except:
    #             return {"status": True, "info": f"{bucket_block[i]}가 활성화되어 있습니다."}
    #     return {"status": True, "info": f"bucket_block가 활성화되어 있습니다."}

    #  버킷에 대해 블록 공개 액세스가 있는지 확인
    def s3_check_s3_bucket_public_access(self):
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_policy = self.s3_client.get_bucket_policy_status(Bucket=bucket_name)

            if bucket_policy['PolicyStatus']['IsPublic']:
                pass
            else:
                return {"status": False, "info": f"S3 버킷 {bucket_name}: 블록 공개 액세스가 비활성화되어 있습니다."}
        return {"status": True, "info": f"S3 버킷 {bucket_name}: 블록 공개 액세스가 활성화되어 있습니다."}

    # 계정 수준에서 모든 S3 공개 액세스가 차단되어 있는지 확인
    # def s3_check_account_level_s3_public_access_block(self):
    #     s3_control = boto3.client('s3control')
    #
    #     # 계정 ID 가져오기
    #     for user in self.users:
    #         account_id = s3_control.create_access_point()['AccountId']
    #         bucket_access = self.s3_client.get_public_access_block(AccountId=account_id)
    #         if self.s3_check_no_account_level_s3_public_access_block(bucket_access):
    #             pass
    #         else:
    #             return {"status": False, "info": f"계정 {account_id}: 공개 액세스 차단이 비활성화되어 있습니다."}
    #     return {"status": True, "info": f"모든 계정이 공개 액세스 차단이 활성화되어 있습니다."}

    def s3_check_no_account_level_s3_public_access_block(bucket_access):
        bucket_block = bucket_access['PublicAccessBlockConfiguration']
        print(bucket_block)

        for i in range(len(bucket_block)):
            print(bucket_block)
            # 'BlockPublicAcls' 'IgnorePublicAcls' 'BlockPublicPolicy' 'RestrictPublicBuckets'
            try:
                if bucket_block[i] is None:
                    print("[FAIL]", f"{bucket_block[i]}가 비활성화되어 있습니다.")
                    return {"status": False, "info": f"{bucket_block[i]}가 비활성화되어 있습니다."}
            except:
                print("[PASS]", f"모든 버킷이 활성화되어 있습니다.")
        return {"status": True, "info": f"모든 버킷이 활성화되어 있습니다."}

    # S3 버킷이 ACL을 사용하지 못하도록 설정되어 있는지 확인
    # def s3_check_s3_bucket_use_acl(self):
    #     for bucket in self.s3_buckets:
    #         bucket_name = bucket['Name']
    #         print(bucket_name)
    #         bucket_access = self.get_bucket_acl(Bucket=strbucket_name)
    #         for grant in bucket_access['Grants']:
    #             if bucket_name in grant.get('Grantee', {}).get('URI', ''):
    #                 return {"status": False, "info": f"S3 버킷 {bucket_name}: ACL 허용되어 있습니다."}
    #     return {"status": True, "info": f"ACL 비허용되어 있습니다."}

    # S3 버킷에 서버 측 암호화가 되어 있는지 확인
    def s3_check_s3_bucket_encryption(self):
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_encryption = self.get_bucket_encryption(Bucket=bucket_name)

            if 'ServerSideEncryptionConfiguration' in bucket_encryption:
                pass
            else:
                return {"status": False, "info": f"S3 버킷 {bucket_name}: 서버 측에 암호화가 되어 있지 않습니다."}
        return {"status": True, "info": f"S3 버킷 서버 측에 암호화가 되어 있습니다."}

    # S3 버킷이 MFA 삭제가 가능한지 확인
    def s3_check_s3_bucket_mfa_delete(self):
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_versioning = self.get_bucket_versioning(Bucket=bucket_name)

            if 'MFADelete' in bucket_versioning and bucket_versioning['MFADelete'] == 'Enabled':
                pass
            else:
                return {"status": False, "info": f"S3 버킷 {bucket_name}: MFA 삭제가 불가능합니다."}
        return {"status": True, "info": f"S3 버킷 MFA 삭제가 가능합니다."}

    ##########################################################

    # S3 버킷의 객체 잠금 상태를 확인하고 딕셔너리로 결과를 반환합니다.
    def s3_check_s3_bucket_object_lock(self):
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)

            if 'Status' in bucket_versioning and bucket_versioning['Status'] == 'Enabled':
                pass
            else:
                return {"status": False, "info": f"S3 버킷 {bucket_name}: 객체 잠금이 활성화되어 있지 않습니다."}
        return {"status": True, "info": f"모든 S3 버킷에서 객체 잠금이 활성화되어 있습니다."}

        # S3 버킷의 정책 존재 여부를 확인하고 딕셔너리로 결과를 반환합니다.

    def s3_check_s3_bucket_policy(self):
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)

            if not bucket_policy:
                pass
            else:
                return {"status": False, "info": f"S3 버킷 {bucket_name}: 버킷 정책이 있습니다."}
        return {"status": True, "info": f"버킷 정책이 없습니다."}

    # S3 버킷의 안전한 전송 정책 존재 여부를 확인하고 딕셔너리로 결과를 반환합니다.
    def s3_check_s3_bucket_secure_transport_policy(self):
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)

            if not bucket_policy:
                return {"status": False, "info": f"S3 버킷 {bucket_name}: 안전하지 않은 전송에 대해 요청 거부하는 정책이 없습니다."}

        return {"status": True, "info": f"S3 버킷 {bucket_name}: 안전하지 않은 전송에 대해 요청 거부하는 정책이 있습니다."}

    # S3 버킷의 SSL 엔드포인트 사용 여부를 확인하고 딕셔너리로 결과를 반환합니다.
    def s3_check_s3_ssl_endpoint(self):
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)

            if not bucket_policy:
                return {"status": False, "info": f"S3 버킷 {bucket_name}: S3 SSL 엔드포인트를 사용하지 않습니다."}
        return {"status": True, "info": f"S3 SSL 엔드포인트를 사용하여 HTTPS를 통해 데이터를 전송할 수 있습니다."}

    # S3 버킷의 서버 측 암호화 상태를 확인하고 딕셔너리로 결과를 반환합니다.
    def s3_check_s3_server_side_encryption(self):
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)

            if not bucket_policy:
                return {"status": False,
                        "info": f"S3 버킷 {bucket_name}: x-amz-server-side-encryption(서버 측 암호화) 헤더가 포함되지 않는 경우, 객체 업로드 (S3:PutObject) 권한을 거부하고 있지 않습니다."}
        return {"status": True,
                "info": f"x-amz-server-side-encryption(서버 측 암호화) 헤더가 포함되지 않는 경우, 객체 업로드 (S3:PutObject) 권한을 거부하고 있습니다."}

    # S3 버킷의 버전 관리 상태를 확인하고 딕셔너리로 결과를 반환합니다.
    def s3_check_s3_bucket_versioning(self):
        results = []
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)

            if 'Status' in bucket_versioning and bucket_versioning['Status'] == 'Enabled':
                pass
            else:
                return {"status": False, "info": f"S3 버킷 {bucket_name}: 버킷에 저장된 모든 객체 보존 및 복원이 (자동화) 되어 있지 않습니다."}
        return {"status": True, "info": f"버킷에 저장된 모든 객체 보존 및 복원이 (자동화) 되어 있습니다."}

    # S3 버킷의 ACL(Access Control List)을 확인하고 딕셔너리로 결과를 반환합니다.
    def s3_check_s3_bucket_acl(self):
        results = []
        for bucket in self.s3_buckets:
            bucket_name = bucket['Name']
            bucket_acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)

            all_accounts = ['http://acs.amazonaws.com/groups/global/AllUsers',
                            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']

            for grant in bucket_acl.get('Grants', []):
                grantee = grant.get('Grantee', {}).get('URI', '')

                if grantee in all_accounts:
                    return {"status": False, "info": f"S3 버킷 {bucket_name}: 모든 S3 계정 수준에서 접근이 허용되고 있습니다."}

        return {"status": True, "info": f"모든 S3 계정 수준에서 접근이 금지되어 있습니다."}


def s3_boto3(key_id, secret, region):
    s3 = S3boto3(key_id, secret, region)  # 클래스의 인스턴스 생성

    s3_check_list = get_s3_check_list()
    result = []

    for method in s3_check_list:
        print(method)
        if hasattr(s3, method):
            m = getattr(s3, method)
            if callable(m):
                buf = m()
                buf['check_name'] = method[3:].upper()
                result.append(buf)
            else:
                result.append({"check_name": None, "status": False, "info": "체크 함수를 실행시키는 과정에서 문제가 발생하였습니다."})
        else:
            result.append({"check_name": None, "status": False, "info": "AWS 연결에 문제가 발생하였습니다. 액세스 아이디와 키를 재설정 해주세요."})
    print(result)
    return result


def get_s3_check_list():
    return [
        # 's3_check_s3_public_access_block',
        's3_check_s3_bucket_public_access',
        # 's3_check_account_level_s3_public_access_block',
        # 's3_check_s3_bucket_use_acl',
        # 's3_check_s3_bucket_encryption',
        # 's3_check_s3_bucket_mfa_delete',

        's3_check_s3_bucket_object_lock',
        's3_check_s3_bucket_policy',
        's3_check_s3_bucket_secure_transport_policy',
        's3_check_s3_ssl_endpoint',
        's3_check_s3_server_side_encryption',
        's3_check_s3_bucket_versioning',
        's3_check_s3_bucket_acl'
    ]
