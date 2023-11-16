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
        '주의 사항!'
    )
    EBS_DEFAULT_ENCRYPTION = 'ec2_ebs_default_encryption'
    EBS_PUBLIC_SNAPSHOT = 'ec2_ebs_public_snapshot'
    EBS_SNAPSHOTS_ENCRYPTED = 'ec2_ebs_snapshots_encrypted'
    EBS_VOLUME_ENCRYPTION = 'ec2_ebs_volume_encryption'

    ELASTIC_IP_SHODAN = 'ec2_elastic_ip_shodan'
    ELASTIC_IP_UNASSIGNED = 'ec2_elastic_ip_unassgined'
    INSTANCE_DETAILED_MONITORING_ENABLED = 'ec2_instance_detailed_monitoring_enabled'
    INSTANCE_IMDSV2_ENABLED = 'ec2_instance_imdsv2_enabled'
    INSTANCE_INTERNET_FACING_WITH_INSTANCE_PROFILE = 'ec2_instance_internet_facing_with_instance_profile'
    
    INSTANCE_MANAGED_BY_SSM = 'ec2_instance_managed_by_ssm'
    INSTANCE_OLDER_THAN_SPECIFIC_DAYS = 'ec2_instance_older_than_specific_days'
    INSTANCE_PROFILE_ATTACHED = 'ec2_instance_profile_attached'
    INSTANCE_PUBLIC_IP = 'ec2_instance_public_ip'
    INSTANCE_SECRETS_USER_DATA = (
        'ec2_instance_secrets_user_data',
        IMPORTANCE.HIGH,
        '주의 사항!'
    )
    # NETWORKACL_ALLOW_INGRESS_ANY_PORT = 'ec2_networkacl_allow_ingress_any_port'
    NETWORKACL_ALLOW_INGRESS_TCP_PORT_22 = 'ec2_networkacl_allow_ingress_tcp_port_22'
    # NETWORKACL_ALLOW_INGRESS_TCP_PORT_3389 = 'ec2_networkacl_allow_ingress_tcp_port_3389'
    # SECURITYGROUP_ALLOW_INGRESS_FROM_INTERNET_TO_ANY_PORT = 'ec2_securitygroup_allow_ingress_from_internet_to_any_port'
    # SECURITYGROUP_ALLOW_INGRESS_FROM_INTERNET_TO_PORT_MONGODB = 'ec2_securitygroup_allow_ingress_from_internet_to_port_mongodb'
    SECURITYGROUP_ALLOW_INGRESS_FROM_INTERNET_TO_TCP_FTP_PORT_20_21 = 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_ftp_port_20_21'
    # SECURITYGROUP_ALLOW_INGRESS_FROM_INTERNET_TO_TCP_PORT_22 = 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22'
    # SECURITYGROUP_ALLOW_INGRESS_FROM_INTERNET_TO_TCP_PORT_3389 = 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389'
    # SECURITYGROUP_ALLOW_INGRESS_FROM_INTERNET_TO_TCP_PORT_CASSANDRA = 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra'
    SECURITYGROUP_ALLOW_INGRESS_FROM_INTERNET_TO_TCP_PORT_MYSQL = 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql'
    SECURITYGROUP_ALLOW_WIDE_OPEN_PUBLIC_IPV4 = 'ec2_securitygroup_allow_wide_open_public_ipv4'
    SECURITYGROUP_DEFAULT_RESTRICT_TRAFFIC = 'ec2_securitygroup_default_restrict_traffic'
    # SECURITYGROUP_FROM_LAUNCH_WIZARD = 'ec2_securitygroup_from_launch_wizard'
    SECURITYGROUP_NOT_USED = 'ec2_securitygroup_not_used'
    # SECURITYGROUP_WITH_MANY_INGRESS_EGRESS_RULES = 'ec2_securitygroup_with_many_ingress_egress_rules'


class Ec2(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_ec2")
    ec2_id = models.CharField(max_length=255, primary_key=True)
    last_modified = models.DateTimeField()
    passed_num = models.IntegerField()
    total_num = models.IntegerField()

    def __str__(self):
        return f"EC2-{str(self.root_id)}-{str(self.ec2_id)}"


class Ec2List(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="ec2_list_records", null=True)
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
