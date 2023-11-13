from enum import Enum



from django.db import models
from django_enumfield import enum
from django_enum_choices.fields import EnumChoiceField

from users.models import User


class IMPORTANCE(enum.Enum):
    HIGH = 0
    MID = 1
    LOW = 2

    __default__ = MID


class S3Enum(Enum):

    CHECK_S3_PUBLIC_ACCESS_BLOCK=(
        's3_check_public_access_block',
        IMPORTANCE.HIGH
    )
    
    CHECK_S3_BUCKET_PUBLIC_ACCESS=(
        's3_check_bucket_public_access',
        IMPORTANCE.HIGH
    )

    CHECK_ACCOUNT_LEVEL_S3_PUBLIC_ACCESS_BLOCK=(
        's3_check_account_level_public_access_block',
        IMPORTANCE.MID
    )

    CHECK_S3_BUCKET_USE_ACL=(
        's3_check_bucket_use_acl',
        IMPORTANCE.HIGH
        
    )

    CHECK_S3_BUCKET_ENCRYPTION=(
        's3_check_bucket_encryption',
        IMPORTANCE.MID
    )

    CHECK_S3_BUCKET_MFA_DELETE=(
        's3_check_bucket_mfa_delete',
        IMPORTANCE.MID
    )


    CHECK_S3_BUCKET_OBJECT_LOCK = (
        's3_check_bucket_object_lock',
        IMPORTANCE.HIGH,
        "S3 버킷 객체 잠금이 활성화되어 있습니다."
    )
    CHECK_S3_BUCKET_POLICY = (
        's3_check_bucket_policy',
        IMPORTANCE.MID,
        "S3 버킷 버킷 정책이 없습니다."
    )
    CHECK_S3_BUCKET_SECURE_TRANSPORT_POLICY = (
        's3_check_bucket_secure_transport_policy',
        IMPORTANCE.MID,
        "S3 버킷 안전한 전송 정책이 있습니다."
    )
    CHECK_S3_SSL_ENDPOINT = (
        's3_check_ssl_endpoint',
        IMPORTANCE.MID,
        "S3 버킷 S3 SSL 엔드포인트를 사용하여 HTTPS를 통해 데이터를 전송할 수 있습니다."
    )
    CHECK_S3_SERVER_SIDE_ENCRYPTION = (
        's3_check_server_side_encryption',
        IMPORTANCE.MID,
        "S3 버킷 x-amz-server-side-encryption(서버 측 암호화) 헤더가 포함되지 않는 경우, 객체 업로드 (S3:PutObject) 권한을 거부하고 있습니다."
    )
    CHECK_S3_BUCKET_VERSIONING = (
        's3_check_bucket_versioning',
        IMPORTANCE.MID,
        "S3 버킷 버킷에 저장된 모든 객체 보존 및 복원이 (자동화) 되어 있습니다."
    )
    CHECK_S3_BUCKET_ACL = (
        's3_check_bucket_acl',
        IMPORTANCE.MID,
        "S3 버킷 모든 S3 계정 수준에서 접근이 금지되어 있습니다."
    )


class S3(models.Model):
    # S3 모델을 정의합니다.
    # 필요한 필드를 추가하세요.
    pass


class S3List(models.Model):
    root_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name="s3_list_records")
    s3_id = models.ForeignKey(S3, on_delete=models.CASCADE, related_name="s3_list_entries")
    check_name = EnumChoiceField(S3Enum)
    check_code = models.CharField(max_length=255)
    importance = enum.EnumField(IMPORTANCE)
    status = models.BooleanField()
    pass_line = models.TextField()
    check_point = models.TextField()
    modified_date = models.DateTimeField()

    def __str__(self):
        return f"S3List-{str(self.s3_id)}"

