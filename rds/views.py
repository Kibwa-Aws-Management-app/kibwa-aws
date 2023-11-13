from datetime import datetime, timezone

from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from rds.models import Rds, RdsList, RdsEnum
from rds.rds import rds_boto3
from users.models import User


def index(request):
    return HttpResponse("Hello, world. You're at the rds index.")


def inspection(request):
    user = request.user

    if user.is_authenticated:
        aws_config = get_object_or_404(User, root_id=user)

        # 액세스 키가 없을 때
        if aws_config.key_id == "":
            return redirect('users:access')

        try:
            result = rds_boto3(aws_config.key_id, aws_config.access_key, aws_config.aws_region)
            rds, result1 = save_rds(user, result)
            result2 = save_rds_list(user, result, rds)
        except:
            return render(request, 'error.html')
        return render(request, 'inspection/inspection.html',
                      {'results': {'check': 'rds', 'result': result1, 'table': result2}})
    return redirect('users:index')


def save_rds(user, result):
    passed_num = sum(r['status'] for r in result)
    total_num = len(result)
    rds, created = Rds.objects.update_or_create(
        root_id=user,
        rds_id='rds_id',
        defaults={
            'last_modified': datetime.now(tz=timezone.utc),
            'passed_num': passed_num,
            'total_num': len(result)
        }
    )
    if not created and iam.last_modified:
        time_difference = datetime.now(tz=timezone.utc) - iam.last_modified
        days_diff = time_difference.days
    else:
        days_diff = 0
    up_result = {'m_time': days_diff, 'pass': passed_num, 'non_pass': total_num-passed_num}
    return rds, up_result


def save_rds_list(user, result, rds):
    rds_enum_dict = {e.name: e for e in RdsEnum}

    for obj in result:
        enum_object = rds_enum_dict.get(obj['check_name'])

        if enum_object is None:
            continue

        RdsList.objects.update_or_create(
            rds_id=rds,
            check_name=enum_object,
            defaults={
                'root_id': user,
                'check_code': 'example_check_code',
                'importance': enum_object.importance,
                'status': obj['status'],
                'pass_line': enum_object.pass_criteria,
                'check_point': obj['info'],
                'modified_date': rds.last_modified
            }
        )

        obj['importance'] = enum_object.importance.name
        obj['date'] = rds.last_modified.strftime('%Y.%m.%d.')

    return result
