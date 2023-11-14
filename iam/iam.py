import boto3
from datetime import datetime, timezone


# PASS == True | FAIL == False
# return { "status" : True, "info": "어쩌구" }
from iam.models import IamEnum


class Iamboto3:
    def __init__(self, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION):
        self.iam_client = boto3.client(
            'iam',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_DEFAULT_REGION
        )
        # 새로운 안전한 비밀번호 정책
        password_policy = {
            'MaxPasswordAge': 90,  # 90일 이내에 만료되도록 요구
            'PasswordReusePrevention': 24,  # 24회 이상 재사용 금지
            'MinimumPasswordLength': 14,  # 최소 길이 14자 요구
            'RequireSymbols': True,  # 특수 문자 사용 요구
            'RequireNumbers': True,  # 숫자 사용 요구
            'RequireUppercaseCharacters': True,  # 대문자 사용 요구
            'RequireLowercaseCharacters': True,  # 소문자 사용 요구
        }
        # AWS IAM에서 비밀번호 정책을 업데이트
        self.iam_client.update_account_password_policy(**password_policy)
        self.users = self.iam_client.list_users()['Users']
        self.iam_list = []
        for user in self.users:
            self.iam_list.append(user['UserName'])

    def get_user_info(self, user_name):
        info = self.iam_client.get_user(UserName=user_name)
        print(info)

    # 인라인 정책에서 관리자 권한 없음
    def iam_inline_policy_no_administrative_privileges(self):
        for username in self.iam_list:
            if self.check_no_user_inline_policy_with_username(username):
                print(f"'{username}'에서 인라인 정책 관리자 권한이 있음이 발견 되었습니다.")
                return {"status": False, "info": f"'{username}'에서 인라인 정책 관리자 권한이 있음이 발견 되었습니다."}
        return {"status": True, "info": "AWS 첨부 정책에서 관리자 권한이 없으므로 안전합니다."}

    def check_no_user_inline_policy_with_username(self, user_name):
        try:
            # iam 계정의 인라인 정책 리스트
            inline_policy = self.iam_client.list_user_policies(UserName=user_name)["PolicyNames"]

            for inline in inline_policy:
                policy = self.iam_client.get_user_policy(
                    UserName=user_name,
                    PolicyName=inline
                )
                check_inline_is_adminAccess = policy['PolicyDocument']['Statement'][0]
                if "*" in check_inline_is_adminAccess['Action'] \
                        and "*" in check_inline_is_adminAccess['Resource']:
                    print("[FAIL] 인라인 정책에 관리자 권한이 있습니다.")
                    return True
        except Exception as e:
            print(f"[FAIL]인라인 정책을 살펴 보던 중 문제가 발생했습니다. {e}")
            return True
        print(f"[PASS] '{user_name}'에 인라인 정책이 없거나, 정책에 관리자 권한이 없습니다. ")
        return False

    # 사용자 정의 첨부 정책에 관리자 권한이 없습니다.
    def iam_user_no_administrator_access(self):
        for username in self.iam_list:
            if self.check_no_AA_in_attach_with_username(username):
                print(f"""{username}에서 첨부 정책에 권한이 있음이 발견 되었습니다.""")
                return {"status": False, "info": f"'{username}'에서 첨부 정책에 권한이 있음이 발견 되었습니다."}
        return {"status": True, "info": "사용자 정의 첨부 정책에 관리자 권한이 없으므로 안전합니다."}

    def check_no_AA_in_attach_with_username(self, user_name):
        try:
            policy = self.iam_client.list_attached_user_policies(UserName=user_name)
            AA = policy['AttachedPolicies']
            for aa in AA:
                print(aa)
                if 'Management' in aa['PolicyName']:
                    print("[FAIL] 첨부 정책에 관리자 권한이 있습니다.")
                    return True
        except Exception as e:
            print(f"첨부 정책 관리자 권한을 확인하던 중 오류가 발생하였습니다. : {e}")
            return True
        print(f"[PASS] '{user_name}'에 첨부 정책에 관리자 권한이 없습니다.")
        return False

    # 사용자 정의 정책을 통한 롤 가정 없음
    def iam_no_custom_policy_permissive_role_assumption(self):
        roles = self.iam_client.list_roles()
        for r in roles['Roles']:
            if self.check_no_role_policy_with_roleName(r['RoleName']):
                return {"status": False, "info": f"'{r['RoleName']}'이 룰 가정을 허용하고 있습니다."}
        return {"status": True, "info": f"룰 가정을 허용하지 않으므로 안전합니다."}

    def check_no_role_policy_with_roleName(self, role_name):
        role = self.iam_client.get_role(RoleName=role_name)
        if role['Role']['AssumeRolePolicyDocument'] is exit:
            print(f"[FAIL] '{role_name}'이 룰 가정을 허용합니다.")
            return True
        print(f"[PASS] '{role_name}'이 룰 가정을 허용하지 않습니다.")
        return False

    # Root 계정을 사용하지 않고 IAM 사용자 또는 역할을 사용합니다. => ROOT 계정 사용하고 있으면 나가리
    def iam_avoid_root_usage(self):
        for u in self.iam_list:
            if self.check_root_user_with_username(u):
                return {"status": False, "info": f"'{u}'이 root 계정입니다."}
        return {"status": True, "info": f"Root 계정을 사용하지 않고 있으므로 안전합니다."}

    def check_root_user_with_username(self, user_name):
        user = self.iam_client.get_user(UserName=user_name)
        root_user = user['User']['Arn'][:4]
        if root_user == 'root':
            print(f"[FAIL] '{user_name}'이 root 계정입니다.")
            return True
        print(f"[PASS] '{user_name}'이 root 계정이 아닙니다.")
        return False

    # FIXME: return 값 수정하기!!!!!
    # 자격증명 비활성화 기간
    def iam_check_disable_days_credentials(self):
        userSet = set()
        results = []

        for user in self.users:
            username = user['UserName']
            access_keys = self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']

            if username in userSet:
                continue  # 이미 출력한 사용자는 continue

            for key in access_keys:
                access_key_id = key['AccessKeyId']
                status = key['Status']
                date_str = key['CreateDate'].strftime("%Y-%m-%d %H:%M:%S")
                create_date = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

                if status == 'Active':
                    inactive_days = (datetime.now(timezone.utc) - create_date).days

                    if inactive_days <= 90:
                        if inactive_days <= 30:
                            message = f"s Access Key {access_key_id} - Inactivity within 30 days."
                        elif 30 < inactive_days <= 45:
                            message = f"s Access Key {access_key_id} - Inactivity exceeding 30 days but within 45 days."
                        else:
                            message = f"Inactivity exceeding 45 days but within 90 days."
                            print(f"[PASS] : User {username}'{message}")
                        userSet.add(username)  # 사용자를 이미 출력한 목록에 추가
                    else:
                        print(f"[FAIL] : User {username}'s Access Key {access_key_id} - exceeds 90 days of inactivity.")
                        userSet.add(username)
                        results.append(username)
                else:
                    print(f"[FAIL] : User {username}' is inactive.")
                    results.append(username)

        if all(result.startswith("[PASS]") for result in results):
            return {"status": True, "info": "모든 사용자의 자격 증명은 90일 이내에 안전합니다."}
        else:
            return {"status": False, "info": f"{results} 사용자의 자격 증명이 90일 이상 비활성 상태입니다."}

    # 사용자의 하드웨어 MFA 사용
    def iam_root_hardware_mfa_enabled(self):
        # Root 계정 하드웨어 MFA 상태 확인
        response = self.iam_client.get_account_summary()
        is_mfa_enabled = response['SummaryMap']['AccountMFAEnabled'] > 0

        if is_mfa_enabled:
            virtual_mfas = self.iam_client.list_virtual_mfa_devices()
            for mfa in virtual_mfas['VirtualMFADevices']:
                if 'root' in mfa['SerialNumber']:
                    print("FAIL : Root account has a virtual MFA instead of a hardware MFA device enabled.")
                    return {"status": False, "info": "Root 계정에서 HW MFA 사용하지 않고 가상 MFA를 사용중입니다."}
            print("PASS : Root account has a hardware MFA device enabled.")
            return {"status": True, "info": "Root 계정에서 하드웨어 MFA 사용하므로 안전합니다."}
        else:
            print("FAIL : Hardware MFA is not enabled for root account.")
            return {"status": False, "info": "Root 계정에서 하드웨어 MFA 사용하지 않습니다."}

    # 사용자의
    def iam_root_mfa_enabled(self):
        # Root 계정 MFA 상태 확인
        response = self.iam_client.get_account_summary()
        is_mfa_enabled = response['SummaryMap']['AccountMFAEnabled'] > 0

        if is_mfa_enabled:
            print("PASS : MFA is enabled for root account.")
            return {"status": True, "info": "Root 계정에서 MFA 사용하므로 안전합니다."}
        else:
            print("FAIL : MFA is not enabled for root account.")
            return {"status": False, "info": "Root 계정에서 MFA 사용하지 않습니다."}

    def iam_user_hardware_mfa_enabled(self):
        rslts = []
        for user in self.users:
            username = user['UserName']

            # 사용자의 MFA 디바이스 확인
            response = self.iam_client.list_mfa_devices(UserName=username)
            if 'MFADevices' in response and len(response['MFADevices']) > 0:
                is_hardware_mfa = False
                for device in response['MFADevices']:
                    if device['DeviceType'] == 'HardwareMFA':
                        is_hardware_mfa = True
                        break

                if is_hardware_mfa:
                    print(f"[PASS] : User '{username}' has hw MFA enabled.")
                else:
                    print(f"[FAIL] : User '{username}' does not have hw MFA enabled.")
                    rslts.append(username)
            else:
               print(f"[FAIL] : User '{username}' does not have any MFA enabled.")
               rslts.append(username)
        if rslts:
            return {"status": False, "info": f"'{rslts}'계정이 하드웨어 MFA를 사용하지 않습니다."}
        else:
            return {"status": True, "info": "HW MFA를 사용중이므로 안전합니다."}

    def iam_user_mfa_enabled(self):
        rslts = []
        for user in self.users:
            username = user['UserName']
            # 사용자 정보 가져오기
            response = self.iam_client.get_user(UserName=username)

            # 사용자의 MFA 활성화 상태 확인
            if 'MFA' in response['User'] and 'MFAEnabled' in response['User']['MFA']:
                if response['User']['MFA']['MFAEnabled']:
                    print(f"[PASS] : User '{username}' is using MFA for AWS console access.")
                else:
                    print(f"[FAIL] : User '{username}' is not using MFA for AWS console access.")
                    rslts.append(username)
                    # return {"status": False, "info": f"'{username}'가 mfa사용 X"}
            else:
                print(f"[FAIL] : User '{username}' does not have MFA information.")
                rslts.append(username)
                # return {"status": False, "info": f"'{username}'의 MFA 정보 없음"}
        if rslts:
            return {"status": False, "info": f"'{rslts}' 유저가 MFA를 사용하지 않습니다."}
        else:
            return {"status": True, "info": "유저가 MFA를 사용중이므로 안전합니다."}

    def iam_administrator_access_with_mfa(self):
        administrator_access_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        results = []

        for user in self.users:
            username = user['UserName']
            response = self.iam_client.list_attached_user_policies(UserName=username)   # 사용자의 관리자 액세스 정책 확인

            for policy in response['AttachedPolicies']:
                if policy['PolicyArn'] == administrator_access_policy_arn:
                    # 사용자가 관리자 액세스 정책을 가지고 있는지
                    response_mfa = self.iam_client.list_mfa_devices()

                    if 'MFADevices' in response_mfa and len(response_mfa['MFADevices']) > 0:
                        print(f"[PASS] : User '{username}' has administrator access with MFA enabled.")  # MFA를 사용
                    else:
                        print(f"[FAIL] : User '{username}' has administrator access with MFA disabled.")  # MFA를 사용X
                        results.append(username)

        if not results:
            print("[PASS] : No users with administrator access and MFA disabled.")
            return {"status": True, "info": "관리자 권한과 MFA가 비활성화된 사용자가 없습니다."}
        return {"status": False, "info": f"'{results}'MFA가 비활성화된 상태에서 관리자 액세스 권한을 가집니다."}

    def iam_password_policy_expires_passwords_within_90_days_or_less(self):
        for user in self.users:
            password_policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            try:
                if password_policy['MaxPasswordAge'] < 90:
                    print(f"PASS - {user['UserName']} password expiration is set lower than 90 days")
                    return {"status": True, "info": f"'{user['UserName']}'의 비밀번호 만료일이 90일 이내로 설정되었습니다."}
                else:
                    print(f"FAIL - {user['UserName']} password expiration is set greater than 90 days")
                    return {"status": False, "info": f"'{user['UserName']}'의 비밀번호 만료일이 90일보다 크게 설정되었습니다."}
            except:
                return {"status": False, "info": f"'{user['UserName']}'의 비밀번호 만료일이 설정되지 않았습니다."}

    def iam_password_policy_reuse_24(self):
        for user in self.users:
            password_policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            try:
                if password_policy['PasswordReusePrevention'] < 24:
                    print(f"PASS - {user['UserName']} password policy reuse prevention is equal to 24.")
                    return {"status": True, "info": f"'{user['UserName']}'의 비밀번호가 24회 보다 적게 재사용 되었습니다."}
                else:
                    print(f"FAIL - {user['UserName']} password policy reuse prevention is less than 24 or not set.")
                    return {"status": False, "info": f"'{user['UserName']}'의 비밀번호가 24회 이상 재사용 되었습니다."}
            except:
                return {"status": False, "info": f"'{user['UserName']}'의 비밀번호 재사용 횟수가 잡히지 않습니다."}

    def iam_password_policy_minimum_length_14(self):
        for user in self.users:
            password_policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            try:
                if password_policy['MinimumPasswordLength'] >= 14:
                    print(f"PASS - {user['UserName']} password policy requires minimum length of 14 characters.")
                    return {"status": True, "info": f"'{user['UserName']}'의 비밀번호 길이가 14자 이상입니다."}
                else:
                    print(f"FAIL- {user['UserName']} password policy does not require minimum length of 14 characters.")
                    return {"status": False, "info": f"'{user['UserName']}'의 비밀번호 길이가 14자보다 짧습니다."}
            except:
                return {"status": False, "info": f"'{user['UserName']}'의 비밀번호가 제대로 설정되지 않았습니다."}

    def iam_password_policy_symbol(self):
        for user in self.users:
            password_policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            try:
                if password_policy['RequireSymbols']:
                    print(f"PASS - {user['UserName']} password policy requires at least one symbol.")
                    return {"status": True, "info": f"'{user['UserName']}'의 비밀번호에 특수문자가 사용되었습니다."}
                else:
                    print(f"FAIL - {user['UserName']} password policy does not require at least one symbol.")
                    return {"status": False, "info": f"'{user['UserName']}'의 비밀번호에 특수문자가 사용되지 않았습니다."}
            except:
                print(f"PASS - {user['UserName']} password policy requires at least one symbol.")
                return {"status": False, "info": f"'{user['UserName']}'의 비밀번호가 제대로 설정되지 않았습니다."}

    def iam_password_policy_number(self):
        for user in self.users:
            password_policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            try:
                if password_policy['RequireNumbers']:
                    print(f"PASS - {user['UserName']} password policy requires at least one number.")
                    return {"status": True, "info": f"'{user['UserName']}'의 비밀번호에 숫자가 사용되었습니다."}
                else:
                    print(f"FAIL - {user['UserName']} password policy does not require at least one number.")
                    return {"status": False, "info": f"'{user['UserName']}'의 비밀번호에 숫자가 사용되지 않았습니다."}
            except:
                return {"status": False, "info": f"'{user['UserName']}'의 비밀번호에 제대로 설정되지 않았습니다."}

    def iam_password_policy_uppercase(self):
        for user in self.users:
            password_policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            try:
                if password_policy['RequireUppercaseCharacters']:
                    print(f"PASS - {user['UserName']} password policy require at least one uppercase letter.")
                    return {"status": True, "info": f"'{user['UserName']}'의 비밀번호에 대문자가 포함되었습니다."}
                else:
                    print(f"FAIL - {user['UserName']} password policy does not requires at least one uppercase letter.")
                    return {"status": False, "info": f"'{user['UserName']}'의 비밀번호에 대문자가 포함되지 않았습니다."}
            except:
                return {"status": False, "info": f"'{user['UserName']}'의 비밀번호에 제대로 설정되지 않았습니다."}

    def iam_password_policy_lowercase(self):
        for user in self.users:
            password_policy = self.iam_client.get_account_password_policy()['PasswordPolicy']
            try:
                if password_policy['RequireLowercaseCharacters']:
                    print(f"PASS - {user['UserName']} password policy requires at least one lowercase letter.")
                    return {"status": True, "info": f"'{user['UserName']}'의 비밀번호에 소문자가 포함되었습니다."}
                else:
                    print(f"FAIL - {user['UserName']} password policy does not requires at least one lowercase letter.")
                    return {"status": False, "info": f"'{user['UserName']}'의 비밀번호에 소문자가 포함되지 않았습니다."}
            except:
                return {"status": False, "info": f"'{user['UserName']}'의 비밀번호에 제대로 설정되지 않았습니다."}

    def iam_no_expired_server_certificates_stored(self):
        for username in self.iam_list:
            response = self.iam_client.list_signing_certificates(UserName=username)
    
            if 'Certificates' in response:
                for certificate in response['Certificates']:
                    if certificate['Status'] == 'Inactive':
                        return {"status": False, "info": f"사용자 '{username}'는 만료된 서버 인증서를 보유하고 있습니다."}
                return {"status": True, "info": f"사용자 '{username}'는 만료된 서버 인증서를 보유하고 있지 않습니다."}
            else:
                return {"status": True, "info": f"사용자 '{username}'는 서버 인증서를 보유하고 있지 않습니다."}
    
    def iam_no_root_access_key(self):
        response = self.iam_client.list_access_keys(UserName='root')
    
        if 'AccessKeyMetadata' in response and len(response['AccessKeyMetadata']) == 0:
            return {"status": True, "info": "루트 계정에 액세스 키가 설정되어 있지 않습니다."}
        else:
            return {"status": False, "info": "루트 계정에 액세스 키가 설정되어 있습니다."}
    
    def iam_rotate_access_key_90_days(self):
        for username in self.iam_list:
            access_keys = self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
    
            for key in access_keys:
                access_key_id = key['AccessKeyId']
                create_date = key['CreateDate']
                inactive_days = (datetime.now(timezone.utc) - create_date).days
    
                if inactive_days >= 90:
                    return {"status": False, "info": f"사용자 '{username}'의 액세스 키 {access_key_id}가 90일 이상 갱신되지 않았습니다."}
                else:
                    return {"status": True, "info": f"사용자 '{username}'의 액세스 키 {access_key_id}가 90일 이내에 갱신되었습니다."}
    
    def iam_user_no_setup_initial_access_key(self):
        for username in self.iam_list:
            access_keys = self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
    
            if len(access_keys) == 0:
                return {"status": True, "info": f"사용자 '{username}'는 초기 액세스 키를 설정하지 않았습니다."}
            else:
                return {"status": False, "info": f"사용자 '{username}'는 초기 액세스 키를 설정하였습니다."}
    
    def iam_user_two_active_access_key(self):
        for username in self.iam_list:
            access_keys = self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            active_keys = [key for key in access_keys if key['Status'] == 'Active']
    
            if len(active_keys) >= 2:
                return {"status": True, "info": f"사용자 '{username}'는 두 개 이상의 활성 액세스 키를 보유하고 있습니다."}
            else:
                return {"status": False, "info": f"사용자 '{username}'는 두 개 이상의 활성 액세스 키를 보유하고 있지 않습니다."}



def iam_boto3(key_id, secret, region):
    iam = Iamboto3(key_id, secret, region)  # 클래스의 인스턴스 생성

    check_list = get_check_list()
    result = []

    for method in check_list:
        if hasattr(iam, method):
            m = getattr(iam, method)
            if callable(m):
                print(m)
                buf = m()
                buf['check_name'] = method[4:].upper()
                result.append(buf)
            else:
                result.append({"check_name": None, "status": False, "info": "체크 함수를 실행시키는 과정에서 문제가 발생하였습니다."})
        else:
            result.append({"check_name": None, "status": False, "info": "AWS 연결에 문제가 발생하였습니다. 액세스 아이디와 키를 재설정 해주세요."})

    return result


def get_check_list():
    return [
        'iam_inline_policy_no_administrative_privileges',
        'iam_user_no_administrator_access',
        'iam_no_custom_policy_permissive_role_assumption',
        'iam_avoid_root_usage',
        'iam_administrator_access_with_mfa',
        'iam_check_disable_days_credentials',
        'iam_user_mfa_enabled',
        'iam_user_hardware_mfa_enabled',
        'iam_root_mfa_enabled',
        'iam_root_hardware_mfa_enabled',
        'iam_password_policy_expires_passwords_within_90_days_or_less',
        'iam_password_policy_reuse_24',
        'iam_password_policy_minimum_length_14',
        'iam_password_policy_symbol',
        'iam_password_policy_number',
        'iam_password_policy_uppercase',
        'iam_password_policy_lowercase'
        'iam_no_expired_server_certificates_stored',
        'iam_no_root_access_key',
        'iam_rotate_access_key_90_days',
        'iam_user_no_setup_initial_access_key',
        'iam_user_two_active_access_key'
    ]
