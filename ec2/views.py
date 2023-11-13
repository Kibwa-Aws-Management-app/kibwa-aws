from datetime import datetime, timezone

from django.shortcuts import render, redirect, get_object_or_404

from django.http import HttpResponse

from ec2.ec2 import ec2_boto3
from ec2.models import Ec2, Ec2List, EC2ENUM
from users.models import User


def index(request):
    return HttpResponse("Hello, world. You're at the Ec2 index.")
 

def inspection(request):
    user = request.user
    
    if user.is_authenticated:
        aws_config = get_object_or_404(User, root_id=user)

        # 액세스 키가 없을 때
        if aws_config.key_id == "":
            return redirect('users:access')
        try:
            result = ec2_boto3(aws_config.key_id, aws_config.access_key, aws_config.aws_region)
            ec2, result1 = save_ec2(user, result)
            result2 = save_ec2_list(user, result, ec2)
        except:
            return render(request, 'error.html')
        return render(request, 'inspection/inspection.html',
                      {'results': {'check': 'ec2', 'result': result1, 'table': result2}})
    return redirect('users:index')


def save_ec2(user, result):
    passed_num = sum(r['status'] for r in result)
    total_num = len(result)
    ec2, created = Ec2.objects.update_or_create(
        root_id=user,
        ec2_id='ec2_id',
        defaults={
            'last_modified': datetime.now(tz=timezone.utc),
            'passed_num': passed_num,
            'total_num': len(result)
        }
    )
    if not created and ec2.last_modified:
        time_difference = datetime.now(tz=timezone.utc) - ec2.last_modified
        days_diff = time_difference.days
    else:
        days_diff = 0
    up_result = {'m_time': days_diff, 'pass': passed_num, 'non_pass': total_num-passed_num}
    return ec2, up_result


def save_ec2_list(user, result, ec2):
    ec2_enum_dict = {e.name: e for e in EC2ENUM}

    for obj in result:
        enum_object = ec2_enum_dict.get(obj['check_name'])

        if enum_object is None:
            continue

        Ec2List.objects.update_or_create(
            ec2_id=ec2,
            check_name=enum_object,
            defaults={
                'root_id': user,
                'check_code': 'example_check_code',
                'importance': enum_object.importance,
                'status': obj['status'],
                'pass_line': enum_object.pass_criteria,
                'check_point': obj['info'],
                'modified_date': ec2.last_modified
            }
        )

        obj['importance'] = enum_object.importance.name
        obj['date'] = ec2.last_modified.strftime('%Y.%m.%d.')

    return result





