from datetime import datetime, timezone

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods
from vpc.models import Vpc, VpcList, VpcEnum
from vpc.vpc import vpc_boto3
from users.models import User


def index(request):
    return HttpResponse("Hello, world. You're at the vpc index.")


@require_http_methods(["GET", "POST"])
def inspection(request):
    user = request.user

    if user.is_authenticated:
        aws_config = get_object_or_404(User, root_id=user)

        # 액세스 키가 없을 때
        if aws_config.key_id == "":
            return redirect('users:access')

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            try:
                result = vpc_boto3(aws_config.key_id, aws_config.access_key, aws_config.aws_region)
                vpc, result1 = save_vpc(user, result)
                print("save")
                result2 = save_vpc_list(user, result, vpc)
                return JsonResponse({'results': {'check': 'vpc', 'result': result1, 'table': result2}})
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)
        return render(request, 'vpc/load.html')
    return redirect('users:index')


def save_vpc(user, result):
    passed_num = sum(r['status'] for r in result)
    total_num = len(result)
    vpc, created = Vpc.objects.update_or_create(
        root_id=user,
        vpc_id=str(user),
        defaults={
            'last_modified': datetime.now(tz=timezone.utc),
            'passed_num': passed_num,
            'total_num': total_num
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
    new_result = []

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
        obj['caution'] = enum_object.pass_criteria

        new_result.append(obj)

    return new_result
