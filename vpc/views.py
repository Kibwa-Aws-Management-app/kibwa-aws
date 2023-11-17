from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from vpc.models import Vpc, VpcList, VpcEnum
from vpc.vpc import vpc_boto3
from users.models import User
from datetime import datetime, timezone


def index(request):
    return HttpResponse("Hello, world. You're at the vpc index.")


def inspection(request):
    user = request.user

    if user.is_authenticated:
        aws_config = get_object_or_404(User, root_id=user)

        # 액세스 키가 없을 때
        if aws_config.key_id == "":
            return redirect('users:access')

        result = vpc_boto3(aws_config.key_id, aws_config.access_key, aws_config.aws_region)
        vpc, result1 = save_vpc(user, result)
        result2 = save_vpc_list(user, result, vpc)
       
        return render(request, 'inspection/inspection.html',
                      {'results': {'check': 'vpc', 'result': result1, 'table': result2}})
    return redirect('users:index')


def save_vpc(user, result):
    passed_num = sum(r['status'] for r in result)
    total_num = len(result)
    vpc, created = Vpc.objects.update_or_create(
        root_id=user,
        vpc_id='vpc_id',
        defaults={
            'last_modified': datetime.now(tz=timezone.utc),
            'passed_num': passed_num,
            'total_num': len(result)
        }
    )
    if not created and vpc.last_modified:
        time_difference = datetime.now(tz=timezone.utc) - vpc.last_modified
        days_diff = time_difference.days
    else:
        days_diff = 0
    up_result = {'m_time': days_diff, 'pass': passed_num, 'non_pass': total_num-passed_num}
    return vpc, up_result


def save_vpc_list(user, result, vpc):
    vpc_enum_dict = {e.name: e for e in VpcEnum}

    for obj in result:
        enum_object = vpc_enum_dict.get(obj['check_name'])

        if enum_object is None:
            continue

        VpcList.objects.update_or_create(
            vpc_id=vpc,
            check_name=enum_object,
            defaults={
                'root_id': user,
                'check_code': 'example_check_code',
                'importance': enum_object.importance,
                'status': obj['status'],
                'pass_line': enum_object.pass_criteria,
                'check_point': obj['info'],
                'modified_date': vpc.last_modified
            }
        )

        obj['importance'] = enum_object.importance.name
        obj['date'] = vpc.last_modified.strftime('%Y.%m.%d.')

    return result
