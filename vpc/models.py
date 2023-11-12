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


class VpcEnum(Enum):

    def __new__(cls, value, importance=IMPORTANCE.MID, pass_criteria=''):
        obj = object.__new__(cls)
        obj._value_ = value
        obj.importance = importance
        obj.pass_criteria = pass_criteria
        return obj

    

    CHECK_VPC_FLOW_LOGS=(
         'vpc_check_flow_logs',
          IMPORTANCE.HIGH
    )

    CHECK_VPC_ENDPOINT_PERMISSIONS=(
         'vpc_check_endpoint_permissions',
         IMPORTANCE.HIGH      
    )

    CHECK_VPC_ENDPOINT_TRUSTED_ACCOUNT_WITH_ARN= 'vpc_check_endpoint_trusted_account_with_arn'
    CHECK_VPC_ENDPOINT_WITH_TWO_ACCOUNT_IDS_ONE_TRUSTED_ONE_NOT='vpc_check_endpoint_with_two_account_ids_one_trusted_one_not'
    CHECK_VPC_ROUTING_TABLE_PEERING='vpc_check_routing_table_peering'
    CHECK_VPC_SUBNETS='vpc_check_subnets'
    CHECK_VPC_SUBNET_AVAILABILITY_ZONE='vpc_check_subnet_availability_zone'
    CHECK_ELBV2_LOGGING_ENABLED='elbv2_check_logging_enabled'


            


class Vpc(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_vpc")
    vpc_id = models.CharField(max_length=255, primary_key=True)
    last_modified = models.DateTimeField()
    passed_num = models.IntegerField()
    total_num = models.IntegerField()

    def __str__(self):
        return f"VPC-{str(self.root_id)}-{str(self.vpc_id)}"


class VpcList(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="vpc_list_records")
    vpc_id = models.ForeignKey(Vpc, on_delete=models.CASCADE, related_name="vpc_list_entries")
    check_name = EnumChoiceField(VpcEnum)
    check_code = models.CharField(max_length=255)
    importance = enum.EnumField(IMPORTANCE)
    status = models.BooleanField()
    pass_line = models.TextField()
    check_point = models.TextField()
    modified_date = models.DateTimeField()

    def __str__(self):
        return f"VpcList-{str(self.vpc_id)}"

