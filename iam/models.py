from enum import Enum

from django.db import models
from django_enum_choices.fields import EnumChoiceField
from django_enumfield import enum
from users.models import User


# django-enumfield
# django-enum-choices


class IMPORTANCE(enum.Enum):
    HIGH = 0
    MID = 1
    LOW = 2

    __default__ = MID


class IamEnum(Enum):

    def __new__(cls, value, importance=IMPORTANCE.MID, pass_criteria=''):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.importance = importance
        obj.pass_criteria = pass_criteria
        return obj

    ADMINISTRATOR_ACCESS_WITH_MFA = (
        'iam_administrator_access_with_mfa',
        IMPORTANCE.HIGH,
        '관리자 권한과 MFA는 항상 활성화된 상태가 되어야 안전합니다.'
    )
    AVOID_ROOT_USAGE = (
        'iam_avoid_root_usage',
        IMPORTANCE.HIGH,
        'Root 계정을 사용하지 않아야 안전합니다.'
    )
    ATTACHED_POLICY_NO_ADMINISTRATIVE_PRIVILEGES = 'iam_attached_policy_no_administrative_privileges'
    CHECK_SAML_PROVIDERS_STS = 'iam_check_saml_providers_sts'
    CUSTOMER_ATTACHED_POLICY_NO_ADMINISTRATIVE_PRIVILEGES = 'iam_customer_attached_policy_no_administrative_privileges'
    CUSTOMER_UNATTACHED_POLICY_NO_ADMINISTRATIVE_PRIVILEGES = 'iam_customer_unattached_policy_no_administrative_privileges'
    CHECK_DISABLE_DAYS_CREDENTIALS = (
        'iam_check_disable_days_credentials',
        IMPORTANCE.MID,
        '사용자의 자격 증명은 90일 이내가 안전합니다.'
    )
    INLINE_POLICY_NO_ADMINISTRATIVE_PRIVILEGES = (
        'iam_inline_policy_no_administrative_privileges',
        IMPORTANCE.MID,
        'AWS 첨부 정책은 관리자 권한이 없어야 안전합니다.'
    )
    NO_CUSTOM_POLICY_PERMISSIVE_ROLE_ASSUMPTION = (
        'iam_no_custom_policy_permissive_role_assumption',
        IMPORTANCE.MID,
        '룰 가정을 허용하지 않아야 안전합니다.'
    )
    NO_EXPIRED_SERVER_CERTIFICATES_STORED = 'iam_no_expired_server_certificates_stored'
    NO_ROOT_ACCESS_KEY = 'iam_no_root_access_key'
    PASSWORD_POLICY_EXPIRES_WITHIN_90_DAYS_OR_LESS = (
        'iam_password_policy_expires_passwords_within_90_days_or_less',
        IMPORTANCE.HIGH,
        '비밀번호는 90일 마다 바꿔야 안전합니다.'
    )
    PASSWORD_POLICY_MINIMUM_LENGTH_14 = (
        'iam_password_policy_minimum_length_14',
        IMPORTANCE.HIGH,
        '비밀번호 길이는 14자 보다 길어야 안전합니다.'
    )
    PASSWORD_POLICY_NUMBER = (
        'iam_password_policy_number',
        IMPORTANCE.HIGH,
        '비밀번호에는 숫자가 포함되어야 안전합니다.'
    )
    PASSWORD_POLICY_LOWERCASE = (
        'iam_password_policy_lowercase',
        IMPORTANCE.HIGH,
        '비밀번호에는 소문자가 포함되어야 안전합니다.'
    )
    PASSWORD_POLICY_REUSE_24 = (
        'iam_password_policy_reuse_24',
        IMPORTANCE.HIGH,
        '비밀번호는 24번이상 반복하여 사용할 수 없습니다.'
    )
    PASSWORD_POLICY_SYMBOL = (
        'iam_password_policy_symbol',
        IMPORTANCE.HIGH,
        '비밀번호에는 특수문자가 포함되어야 안전합니다.'
    )
    PASSWORD_POLICY_UPPERCASE = (
        'iam_password_policy_uppercase',
        IMPORTANCE.HIGH,
        '비밀번호에는 대문자가 포함되어야 안전합니다.'
    )
    POLICY_ALLOWS_PRIVILEGE_ESCALATION = 'iam_policy_allows_privilege_escalation'
    POLICY_ATTACHED_ONLY_TO_GROUP_OR_ROLES = 'iam_policy_attached_only_to_group_or_roles'
    POLICY_NO_FULL_ACCESS_TO_CLOUDTRAIL = 'iam_policy_no_full_access_to_cloudtrail'
    POLICY_NO_FULL_ACCESS_TO_KMS = 'iam_policy_no_full_access_to_kms'
    ROLE_ADMINISTRATOR_ACCESS_POLICY = 'iam_role_administratoraccess_policy'
    ROLE_CROSS_ACCOUNT_READ_ONLY_ACCESS_POLICY = 'iam_role_cross_account_readonlyaccess_policy'
    ROLE_SERVICE_CONFUSED_DEPUTY_PREVENTION = 'iam_role_cross_service_confused_deputy_prevention'
    ROOT_HARDWARE_MFA_ENABLED = (
        'iam_root_hardware_mfa_enabled',
        IMPORTANCE.LOW,
        'Root 계정에서 하드웨어 MFA를 사용해야 안전합니다.'
    )
    ROOT_MFA_ENABLED = (
        'iam_root_mfa_enabled',
        IMPORTANCE.LOW,
        'Root 계정에서 MFA를 사용해야 안전합니다.'
    )
    ROTATE_ACCESS_KEY_90_DAYS = 'iam_rotate_access_key_90_days'
    SECURITY_AUDIT_ROLE_CREATED = 'iam_securityaudit_role_created'
    SUPPORT_ROLE_CREATED = 'iam_support_role_created'
    USER_HARDWARE_MFA_ENABLED = (
        'iam_user_hardware_mfa_enabled',
        IMPORTANCE.MID,
        '하드웨어 MFA를 사용해야 안전합니다.'
    )
    USER_MFA_ENABLED = (
        'iam_user_mfa_enabled',
        IMPORTANCE.MID,
        'MFA가 활성화되어 있어야 안전합니다.'
    )
    USER_NO_ADMINISTRATOR_ACCESS = (
        'iam_user_no_administrator_access',
        IMPORTANCE.HIGH,
        '사용자 정의 첨부 정책에는 관리자 권한이 없어야 안전합니다.'
    )
    USER_NO_SETUP_INITIAL_ACCESS_KEY = 'iam_user_no_setup_initial_access_key'
    USER_TWO_ACTIVE_ACCESS_KEYS = 'iam_user_two_active_access_keys'


class Iam(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_iam")
    iam_id = models.CharField(max_length=255, primary_key=True)
    last_modified = models.DateTimeField()
    passed_num = models.IntegerField()
    total_num = models.IntegerField()

    def __str__(self):
        return f"IAM-{str(self.root_id)}-{str(self.iam_id)}"


class IamList(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="iam_list_records")
    iam_id = models.ForeignKey(Iam, on_delete=models.CASCADE, related_name="iam_list_entries")
    check_name = EnumChoiceField(IamEnum)
    check_code = models.CharField(max_length=255)
    importance = enum.EnumField(IMPORTANCE)
    status = models.BooleanField()
    pass_line = models.TextField()
    check_point = models.TextField()
    modified_date = models.DateTimeField()

    def __str__(self):
        return f"IamList-{str(self.iam_id)}"
