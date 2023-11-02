from datetime import datetime, timezone

from django.shortcuts import render, redirect, get_object_or_404

from django.http import HttpResponse

from iam.iam import iam_boto3
from iam.models import Iam, IamList, IamEnum
from users.models import User


def index(request):
    return HttpResponse("Hello, world. You're at the iam index.")


def inspection(request):
    user = request.user

    if user.is_authenticated:
        aws_config = get_object_or_404(User, root_id=user)

        # 액세스 키가 없을 때
        if aws_config.key_id == "":
            return redirect('users:access')

        try:
            result = iam_boto3(aws_config.key_id, aws_config.access_key, aws_config.aws_region)
            iam = save_iam(user, result)
            result = save_iam_list(user, result, iam)
        except:
            return render(request, 'error.html')
        return render(request, 'inspection/inspection.html', {'results': result})
    return redirect('users:index')


def save_iam(user, result):
    passed_num = sum(r['status'] for r in result)

    iam, created = Iam.objects.update_or_create(
        root_id=user,
        iam_id='iam_id',
        defaults={
            'last_modified': datetime.now(tz=timezone.utc),
            'passed_num': passed_num,
            'total_num': len(result)
        }
    )

    return iam


def save_iam_list(user, result, iam):
    iam_enum_dict = {e.name: e for e in IamEnum}

    for obj in result:
        enum_object = iam_enum_dict.get(obj['check_name'])

        if enum_object is None:
            continue

        IamList.objects.update_or_create(
            iam_id=iam,
            check_name=enum_object,
            defaults={
                'root_id': user,
                'check_code': 'example_check_code',
                'importance': enum_object.importance,
                'status': obj['status'],
                'pass_line': enum_object.pass_criteria,
                'check_point': obj['info'],
                'modified_date': iam.last_modified
            }
        )

        obj['importance'] = enum_object.importance.name
        obj['date'] = iam.last_modified.strftime('%Y.%m.%d.')

    return result





