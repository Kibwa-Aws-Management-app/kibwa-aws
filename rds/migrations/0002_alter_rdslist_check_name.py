# Generated by Django 4.2.6 on 2023-11-16 18:07

from django.db import migrations
import django_enum_choices.choice_builders
import django_enum_choices.fields
import rds.models


class Migration(migrations.Migration):

    dependencies = [
        ('rds', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='rdslist',
            name='check_name',
            field=django_enum_choices.fields.EnumChoiceField(choice_builder=django_enum_choices.choice_builders.value_value, choices=[("('rds_check_subnet_availability', <IMPORTANCE.HIGH: 0>, 'RDS 서브넷 그룹 내 불필요한 가용 영역이 존재하지 않습니다.')", "('rds_check_subnet_availability', <IMPORTANCE.HIGH: 0>, 'RDS 서브넷 그룹 내 불필요한 가용 영역이 존재하지 않습니다.')"), ("('rds_check_encryption', <IMPORTANCE.MID: 1>, 'RDS 데이터베이스 암호화가 비활성화되어 있습니다.')", "('rds_check_encryption', <IMPORTANCE.MID: 1>, 'RDS 데이터베이스 암호화가 비활성화되어 있습니다.')"), ("('rds_check_logging', <IMPORTANCE.MID: 1>, 'CloudWatch 로그 스트림으로 보관하고 있습니다.')", "('rds_check_logging', <IMPORTANCE.MID: 1>, 'CloudWatch 로그 스트림으로 보관하고 있습니다.')"), ("('rds_check_public_access', <IMPORTANCE.MID: 1>, 'RDS에 대해 Public Access가 허용되어 있지 않습니다.')", "('rds_check_public_access', <IMPORTANCE.MID: 1>, 'RDS에 대해 Public Access가 허용되어 있지 않습니다.')"), ("('rds_db_creation_deletion_privileges', <IMPORTANCE.MID: 1>, 'DBE만 데이터베이스 생성/삭제를 할 수 있도록 설정되어 있습니다.')", "('rds_db_creation_deletion_privileges', <IMPORTANCE.MID: 1>, 'DBE만 데이터베이스 생성/삭제를 할 수 있도록 설정되어 있습니다.')")], enum_class=rds.models.RdsEnum, max_length=101),
        ),
    ]
