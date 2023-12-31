from datetime import datetime, timezone

from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods
from s3.models import S3, S3List, S3Enum
from s3.s3 import s3_boto3
from users.models import User


def index(request):
    return HttpResponse("Hello, world. You're at the s3 index.")


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
                result = s3_boto3(aws_config.key_id, aws_config.access_key, aws_config.aws_region)
                s3, result1 = save_s3(user, result)
                result2 = save_s3_list(user, result, s3)
                return JsonResponse({'results': {'check': 's3', 'result': result1, 'table': result2}})
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)
        return render(request, 's3/load.html')
    return redirect('users:index')


def save_s3(user, result):
    passed_num = sum(r['status'] for r in result)
    total_num = len(result)
    s3, created = S3.objects.update_or_create(
        root_id=user,
        s3_id=str(user),
        defaults={
            'last_modified': datetime.now(tz=timezone.utc),
            'passed_num': passed_num,
            'total_num': len(result)
        }
    )
    if not created and s3.last_modified:
        time_difference = datetime.now(tz=timezone.utc) - s3.last_modified
        days_diff = time_difference.days
    else:
        days_diff = 0
    up_result = {'m_time': days_diff, 'pass': passed_num, 'non_pass': total_num-passed_num}
    return s3, up_result


def save_s3_list(user, result, s3):
    s3_enum_dict = {e.name: e for e in S3Enum}
    new_result = []

    for obj in result:
        enum_object = s3_enum_dict.get(obj['check_name'])

        if enum_object is None:
            continue

        S3List.objects.update_or_create(
            s3_id=s3,
            check_name=enum_object,
            defaults={
                'root_id': user,
                'check_code': 'example_check_code',
                'importance': enum_object.importance,
                'status': obj['status'],
                'pass_line': enum_object.pass_criteria,
                'check_point': obj['info'],
                'modified_date': s3.last_modified
            }
        )

        obj['importance'] = enum_object.importance.name
        obj['date'] = s3.last_modified.strftime('%Y.%m.%d.')
        obj['caution'] = enum_object.pass_criteria
        new_result.append(obj)

    return new_result
