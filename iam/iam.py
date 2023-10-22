import boto3
from datetime import datetime, timezone

class iam:
    def __init__(self):
        self.iam_client = boto3.client('iam')
        self.users = self.iam_client.list_users()['Users']
        self.iam_list = []
        for user in self.users:
            self.iam_list.append(user['UserName'])

    # 유저의 정보 가져오기
    def get_user_info(self, user_name):
        info = self.iam_client.get_user(UserName=user_name)
        print(info)

    def check_iam_user_credentials(self):
        userSet = set() 

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
                        print(f"PASS : User {username}'{message}")
                        userSet.add(username)  # 사용자를 이미 출력한 목록에 추가
                    else:
                        print(f"FAIL : User {username}'s Access Key {access_key_id} - exceeds 90 days of inactivity.")
                        userSet.add(username)  # 사용자를 이미 출력한 목록에 추가
                else:
                    print(f"User {username}' is inactive.")

    def check_administrator_access_with_mfa(self):
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
                        print(f"PASS : User '{username}' has administrator access with MFA enabled.")  # MFA를 사용
                    else:
                        print(f"FAIL : User '{username}' has administrator access with MFA disabled.")  # MFA를 사용X
                        results.append(username)

        if not results:
            print("PASS : No users with administrator access and MFA disabled.")

    def check_root_hw_mfa_enabled(self):
        # Root 계정 하드웨어 MFA 상태 확인
        response = self.iam_client.get_account_summary()
        is_mfa_enabled = response['SummaryMap']['AccountMFAEnabled'] > 0

        if is_mfa_enabled:
            virtual_mfas = self.iam_client.list_virtual_mfa_devices()
            for mfa in virtual_mfas['VirtualMFADevices']:
                if 'root' in mfa['SerialNumber']:
                    print("FAIL : Root account has a virtual MFA instead of a hardware MFA device enabled.")
                    return
            print("PASS : Root account has a hardware MFA device enabled.")
        else:
            print("FAIL : Hardware MFA is not enabled for root account.")

    def check_root_mfa_enabled(self):
        # Root 계정 MFA 상태 확인
        response = self.iam_client.get_account_summary()
        is_mfa_enabled = response['SummaryMap']['AccountMFAEnabled'] > 0

        if is_mfa_enabled:
            print("PASS : MFA is enabled for root account.")
        else:
            print("FAIL : MFA is not enabled for root account.")

    def check_user_hardware_mfa_enabled(self):
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
                    print(f"PASS : User '{username}' has hw MFA enabled.")
                else:
                    print(f"FAIL : User '{username}' does not have hw MFA enabled.")
            else:
                print(f"FAIL : User '{username}' does not have any MFA enabled.")

    def check_user_mfa_enabled(self):
        for user in self.users:
            username = user['UserName']

            # 사용자 정보 가져오기
            response = self.iam_client.get_user(UserName=username)
            
            # 사용자의 MFA 활성화 상태 확인
            if 'MFA' in response['User'] and 'MFAEnabled' in response['User']['MFA']:
                if response['User']['MFA']['MFAEnabled']:
                    print(f"PASS : User '{username}' is using MFA for AWS console access.")
                else:
                    print(f"FAIL : User '{username}' is not using MFA for AWS console access.")
            else:
                print(f"User '{username}' does not have MFA information.")

if __name__ == "__main__":
    iam_instance = iam()  # 클래스의 인스턴스 생성
    iam_instance.check_administrator_access_with_mfa()
    print("----------")
    iam_instance.check_iam_user_credentials()
    print("----------")
    iam_instance.check_root_hw_mfa_enabled()
    print("----------")
    iam_instance.check_root_mfa_enabled()
    print("----------")
    iam_instance.check_user_hardware_mfa_enabled()
    print("----------")
    iam_instance.check_user_mfa_enabled()