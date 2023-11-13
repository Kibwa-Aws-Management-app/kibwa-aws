from enum import Enum

from django.db import models
from django_enum_choices.fields import EnumChoiceField
from django_enumfield import enum
from users.models import User


class IMPORTANCE(enum.Enum):
    HIGH = 0
    MID = 1
    LOW = 2

    __default__ = MID


class RdsEnum(Enum):
    CHECK_RDS_SUBNET_AVAILABILITY = (
        'rds_check_subnet_availability',
        IMPORTANCE.HIGH,
        "RDS 서브넷 그룹 내 불필요한 가용 영역이 존재하지 않습니다."
    )
    CHECK_RDS_ENCRYPTION = (
        'rds_check_encryption',
        IMPORTANCE.MID,
        "RDS 데이터베이스 암호화가 비활성화되어 있습니다."
    )
    CHECK_RDS_LOGGING = (
        'rds_check_logging',
        IMPORTANCE.MID,
        "CloudWatch 로그 스트림으로 보관하고 있습니다."
    )
    CHECK_RDS_PUBLIC_ACCESS = (
        'rds_check_public_access',
        IMPORTANCE.MID,
        "RDS에 대해 Public Access가 허용되어 있지 않습니다."
    )
    CHECK_DB_CREATION_DELETION_PRIVILEGES = (
        'db_creation_deletion_privileges',
        IMPORTANCE.MID,
        "DBE만 데이터베이스 생성/삭제를 할 수 있도록 설정되어 있습니다."
    )


class Rds(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="user_rds")
    rds_id = models.CharField(max_length=255, primary_key=True)
    last_modified = models.DateTimeField()
    passed_num = models.IntegerField()
    total_num = models.IntegerField()

    def __str__(self):
        return f"RDS-{str(self.root_id)}-{str(self.rds_id)}"


class RdsList(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="rds_list_records")
    rds_id = models.ForeignKey(Rds, on_delete=models.CASCADE, related_name="rds_list_entries")
    check_name = EnumChoiceField(RdsEnum)
    check_code = models.CharField(max_length=255)
    importance = enum.EnumField(IMPORTANCE)
    status = models.BooleanField()
    pass_line = models.TextField()
    check_point = models.TextField()
    modified_date = models.DateTimeField()

    def __str__(self):
        return f"RDSList-{str(self.rds_id)}"
