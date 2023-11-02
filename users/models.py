from django.contrib.auth.models import PermissionsMixin, AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _


class AWSRegion(models.TextChoices):
    US_EAST_1 = 'us-east-1', _('미국 동부(버지니아 북부)')
    US_EAST_2 = 'us-east-2', _('미국 동부(오하이오)')
    US_WEST_1 = 'us-west-1', _('미국 서부(캘리포니아 북부)')
    US_WEST_2 = 'us-west-2', _('미국 서부(오리건)')
    AF_SOUTH_1 = 'af-south-1', _('아프리카(케이프타운)')
    AP_EAST_1 = 'ap-east-1', _('아시아 태평양(홍콩)')
    AP_SOUTH_2 = 'ap-south-2', _('아시아 태평양(하이데라바드)')
    AP_SOUTHEAST_3 = 'ap-southeast-3', _('아시아 태평양(자카르타)')
    AP_SOUTHEAST_4 = 'ap-southeast-4', _('아시아 태평양(멜버른)')
    AP_SOUTH_1 = 'ap-south-1', _('아시아 태평양(뭄바이)')
    AP_NORTHEAST_3 = 'ap-northeast-3', _('아시아 태평양(오사카)')
    AP_NORTHEAST_2 = 'ap-northeast-2', _('아시아 태평양(서울)')
    AP_SOUTHEAST_1 = 'ap-southeast-1', _('아시아 태평양(싱가포르)')
    AP_SOUTHEAST_2 = 'ap-southeast-2', _('아시아 태평양(시드니)')
    AP_NORTHEAST_1 = 'ap-northeast-1', _('아시아 태평양(도쿄)')
    CA_CENTRAL_1 = 'ca-central-1', _('캐나다(중부)')
    EU_CENTRAL_1 = 'eu-central-1', _('유럽(프랑크푸르트)')
    EU_WEST_1 = 'eu-west-1', _('유럽(아일랜드)')
    EU_WEST_2 = 'eu-west-2', _('유럽(런던)')
    EU_SOUTH_1 = 'eu-south-1', _('유럽(밀라노)')
    EU_WEST_3 = 'eu-west-3', _('유럽(파리)')
    EU_SOUTH_2 = 'eu-south-2', _('유럽(스페인)')
    EU_NORTH_1 = 'eu-north-1', _('유럽(스톡홀름)')
    EU_CENTRAL_2 = 'eu-central-2', _('유럽(취리히)')
    IL_CENTRAL_1 = 'il-central-1', _('이스라엘(텔아비브)')
    ME_SOUTH_1 = 'me-south-1', _('중동(바레인)')
    ME_CENTRAL_1 = 'me-central-1', _('중동(UAE)')
    SA_EAST_1 = 'sa-east-1', _('남아메리카(상파울루)')


class CustomUserManager(BaseUserManager):
    def create_user(self, root_id, password=None, **extra_fields):
        if not root_id:
            raise ValueError('The Root ID must be set')
        user = self.model(root_id=root_id, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, root_id, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(root_id, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    root_id = models.CharField(max_length=200, primary_key=True, unique=True)
    password = models.CharField(max_length=200)
    key_id = models.CharField(max_length=200, default="")
    access_key = models.CharField(max_length=200, default="")
    aws_region = models.CharField(max_length=15, choices=AWSRegion.choices, default=AWSRegion.AP_NORTHEAST_2)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'root_id'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = "user"

    def __str__(self):
        return str(self.root_id)

