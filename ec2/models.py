from enum import Enum

from django.db import models
from django_enumfield import enum
from django_enum_choices.fields import EnumChoiceField

from users.models import User


# django-enumfield
# django-enum-choices


class IMPORTANCE(enum.Enum):
    HIGH = 0
    MID = 1
    LOW = 2

    __default__ = MID


class EC2ENUM(Enum):

    def __new__(cls, value, importance=IMPORTANCE.MID, pass_criteria=''):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.importance = importance
        obj.pass_criteria = pass_criteria
        return obj

    AMI_PUBLIC = (
        'ec2_ami_public',
        IMPORTANCE.HIGH,
        '모든 AMI가 비공개 상태여야 안전합니다.'
    )

    EBS_DEFAULT_ENCRYPTION = (
        'ec2_ebs_default_encryption',
        IMPORTANCE.MID,
        '볼륨이 암호화되어 있어야 안전합니다.'
    )

    EBS_PUBLIC_SNAPSHOT = (
        'ec2_ebs_public_snapshot',
        IMPORTANCE.MID,
        '스냅샷이 비공개 상태여야 안전합니다.'
    )

    EBS_SNAPSHOTS_ENCRYPTED = (
        'ec2_ebs_snapshots_encrypted',
        IMPORTANCE.MID,
        '스냅샷이 암호화되어 있어야 안전합니다.'
    )

    EBS_VOLUME_ENCRYPTION = (
        'ec2_ebs_volume_encryption',
        IMPORTANCE.MID,
        '볼륨이 암호화되어 있어야 안전합니다.'
    )

    '''ELASTIC_IP_SHODAN = (
        'ec2_elastic_ip_shodan',
        IMPORTANCE.LOW,
        '낮은 중요도!'
    )

    ELASTIC_IP_UNASSIGNED = (
        'ec2_elastic_ip_unassgined',
        IMPORTANCE.MID,
        '중요 사항!'
    )

    INSTANCE_DETAILED_MONITORING_ENABLED = (
        'ec2_instance_detailed_monitoring_enabled',
        IMPORTANCE.HIGH,
        '매우 중요한 사항!'
    )

    INSTANCE_IMDSV2_ENABLED = (
        'ec2_instance_imdsv2_enabled',
        IMPORTANCE.MID,
        '낮은 중요도!'
    )

    INSTANCE_INTERNET_FACING_WITH_INSTANCE_PROFILE = (
        'ec2_instance_internet_facing_with_instance_profile',
        IMPORTANCE.MID,
        '중요 사항!'
    )'''

    INSTANCE_MANAGED_BY_SSM = (
        'ec2_instance_managed_by_ssm',
        IMPORTANCE.MID,
        '인스턴스가 ssm에 관리되고 있어야 안전합니다.'
    )

    INSTANCE_OLDER_THAN_SPECIFIC_DAYS = (
        'ec2_instance_older_than_specific_days',
        IMPORTANCE.MID,
        '인스턴스가 특정 날짜 이후 생성되어야 안전합니다.'
    )

    INSTANCE_PROFILE_ATTACHED = (
        'ec2_instance_profile_attached',
        IMPORTANCE.MID,
        '인스턴스가 인스턴스 프로파일과 연결되어야 안전합니다.'
    )

    INSTANCE_PUBLIC_IP = (
        'ec2_instance_public_ip',
        IMPORTANCE.HIGH,
        '인스턴스가 퍼블릭 IP를 보유하고 있어야 안전합니다.'
    )

    INSTANCE_SECRETS_USER_DATA = (
        'ec2_instance_secrets_user_data',
        IMPORTANCE.HIGH,
        '인스턴스의 사용자 데이터에 민감한 정보가 포함되지 않아야 안전합니다.'
    )
    NETWORKACL_ALLOW_INGRESS_TCP_PORT_22 = (
        'ec2_networkacl_allow_ingress_tcp_port_22',
        IMPORTANCE.MID,
        '인스턴스가 TCP 포트 22에 대한 인바운드 트래픽이 차단되어 있어야 안전합니다.'
    )
    SECURITYGROUP_ALLOW_INGRESS_PORT_20_21 = (
        'ec2_securitygroup_allow_ingress_port_20_21',
        IMPORTANCE.MID,
        '인터넷에서 TCP 포트 20,21로의 인바운드 트래픽이 차단되어 있어야 안전합니다.'
    )
    SECURITYGROUP_ALLOW_INGRESS_TCP_PORT_MYSQL = (
        'ec2_securitygroup_allow_ingress_tcp_port_mysql',
        IMPORTANCE.MID,
        '인터넷에서 MySQL DB로의 인바운드 트래픽이 차단되어 있어야 안전합니다.'
    )
    SECURITYGROUP_ALLOW_WIDE_OPEN_PUBLIC_IPV4 = (
        'ec2_securitygroup_allow_wide_open_public_ipv4',
        IMPORTANCE.MID,
        '퍼블릭 IPv4 주소 대역으로의 인바운드 트래픽이 차단되어 있어야 안전합니다.'
    )
    SECURITYGROUP_DEFAULT_RESTRICT_TRAFFIC = (
        'ec2_securitygroup_default_restrict_traffic',
        IMPORTANCE.MID,
        '기본적으로 모든 트래픽이 제한되어 있어야 안전합니다.'
    )
    SECURITYGROUP_NOT_USED = (
        'ec2_securitygroup_not_used',
        IMPORTANCE.MID,
        '보안 그룹이 사용 중이어야 안전합니다.'
    )


class Ec2(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_ec2")
    ec2_id = models.CharField(max_length=255, primary_key=True)
    last_modified = models.DateTimeField()
    passed_num = models.IntegerField()
    total_num = models.IntegerField()

    def __str__(self):
        return f"EC2-{str(self.root_id)}-{str(self.ec2_id)}"


class Ec2List(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="ec2_list_records")
    ec2_id = models.ForeignKey(Ec2, on_delete=models.CASCADE, related_name="ec2_list_entries")
    check_name = EnumChoiceField(EC2ENUM)
    check_code = models.CharField(max_length=255)
    importance = enum.EnumField(IMPORTANCE)
    status = models.BooleanField()
    pass_line = models.TextField()
    check_point = models.TextField()
    modified_date = models.DateTimeField()

    def __str__(self):
        return f"Ec2List-{str(self.ec2_id)}"
