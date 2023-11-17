# Generated by Django 4.2.6 on 2023-11-16 18:38

from django.db import migrations
import django_enum_choices.choice_builders
import django_enum_choices.fields
import iam.models


class Migration(migrations.Migration):

    dependencies = [
        ('iam', '0006_alter_iamlist_check_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='iamlist',
            name='check_name',
            field=django_enum_choices.fields.EnumChoiceField(choice_builder=django_enum_choices.choice_builders.value_value, choices=[('iam_administrator_access_with_mfa', 'iam_administrator_access_with_mfa'), ('iam_avoid_root_usage', 'iam_avoid_root_usage'), ('iam_check_disable_days_credentials', 'iam_check_disable_days_credentials'), ('iam_inline_policy_no_administrative_privileges', 'iam_inline_policy_no_administrative_privileges'), ('iam_no_custom_policy_permissive_role_assumption', 'iam_no_custom_policy_permissive_role_assumption'), ('iam_password_policy_expires_passwords_within_90_days_or_less', 'iam_password_policy_expires_passwords_within_90_days_or_less'), ('iam_password_policy_minimum_length_14', 'iam_password_policy_minimum_length_14'), ('iam_password_policy_number', 'iam_password_policy_number'), ('iam_password_policy_lowercase', 'iam_password_policy_lowercase'), ('iam_password_policy_reuse_24', 'iam_password_policy_reuse_24'), ('iam_password_policy_symbol', 'iam_password_policy_symbol'), ('iam_password_policy_uppercase', 'iam_password_policy_uppercase'), ('iam_root_hardware_mfa_enabled', 'iam_root_hardware_mfa_enabled'), ('iam_root_mfa_enabled', 'iam_root_mfa_enabled'), ('iam_user_hardware_mfa_enabled', 'iam_user_hardware_mfa_enabled'), ('iam_user_mfa_enabled', 'iam_user_mfa_enabled'), ('iam_user_no_administrator_access', 'iam_user_no_administrator_access')], enum_class=iam.models.IamEnum, max_length=60),
        ),
    ]