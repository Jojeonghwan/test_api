# users/utils.py
from rest_framework import status
from test_api.utils import StandardErrorResponse
from typing import Optional, Final
from django.contrib.auth.password_validation import (
    MinimumLengthValidator,
    CommonPasswordValidator,
    NumericPasswordValidator,
)
from django.core.validators import validate_email as django_validate_email
import uuid
from rest_framework.pagination import PageNumberPagination
import datetime


class ValidationErrorStrs:
    """
    validation에서 사용하는 문구 모음 (static하게 사용하기 위함)
    - django에 설정된 에러문구를 그대로 사용할 수도 있지만,
      언어에 따른 처리를 직접 해주기 위해 해당 문구를 사용하는 방식으로 처리
    """

    pw_required: Final = "비밀번호를 입력해 주세요."
    pw_not_match: Final = "비밀번호가 일치하지 않습니다."
    pw_min_length: Final = "비밀번호가 너무 짧습니다. 최소 8 문자를 포함해야 합니다."
    pw_common: Final = "비밀번호가 너무 일상적인 단어입니다."
    pw_numeric: Final = "비밀번호가 전부 숫자로 되어 있습니다."
    email_required: Final = "이메일을 입력해 주세요."
    email_not_valid: Final = "유효한 이메일 주소를 입력하십시오."
    email_exist: Final = "이미 가입한 이메일입니다."
    user_type_required: Final = "유저타입이 필요합니다."
    user_type_not_valid: Final = "올바르지 않은 유저타입 입니다."
    user_auth_failed: Final = "번호 또는 비밀번호가 일치하지 않습니다."
    username_required: Final = "유저이름이 필요합니다."
    phone_required: Final = "번호가 필요합니다."
    user_social_auth_failed: Final = "소셜 로그인에 실패하였습니다."
    user_social_auth_check_failed: Final = "소셜 로그인 체크에 실패하였습니다."


class RegistrationValidationValues:
    def __init__(self, request):
        self.email = request.data.get("email")
        self.phone = request.data.get("phone")
        self.user_type = request.data.get("user_type")
        self.username = request.data.get("username")
        self.password1 = request.data.get("password1")
        self.password2 = request.data.get("password2")


class LoginValidationValues:
    def __init__(self, request):
        self.phone = request.data.get("phone")
        self.password = request.data.get("password")


def validate_password_equality(
    password1: str, password2: str
) -> Optional[StandardErrorResponse]:
    if password1 != password2:
        return StandardErrorResponse(
            detail=[ValidationErrorStrs.pw_not_match],
            code="passwords_do_not_match",
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    return None


def validate_password_format(password: str) -> Optional[StandardErrorResponse]:
    """
    django validator들을 그대로 현상황에선 언어를 상황에 맞게 컨트롤 할 수가 없다고 판단하여
    번거럽더라도 각각 try-except구문으로 구분하여 직접 정의 한 에러문구와 함께 처리
    (한번에 처리하면 어떤 에러인지 알 수 없으므로)
    추후, 더 좋은 방법이 생기면 그것으로 변경할 것
    """
    validate_error_strs = []
    try:
        MinimumLengthValidator().validate(password)
    except Exception:
        validate_error_strs.append(ValidationErrorStrs.pw_min_length)

    try:
        CommonPasswordValidator().validate(password)
    except Exception:
        validate_error_strs.append(ValidationErrorStrs.pw_common)

    try:
        NumericPasswordValidator().validate(password)
    except Exception:
        validate_error_strs.append(ValidationErrorStrs.pw_numeric)

    if len(validate_error_strs) > 0:
        return StandardErrorResponse(
            detail=validate_error_strs,
            code="password_validation_failed",
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    return None


def validate_email(email: str) -> Optional[StandardErrorResponse]:
    try:
        django_validate_email(email)
    except Exception:
        return StandardErrorResponse(
            detail=[ValidationErrorStrs.email_not_valid],
            code="email_not_valid",
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    return None


def validate_registration(
    value_obj: RegistrationValidationValues,
) -> Optional[StandardErrorResponse]:
    # 필수항목 미입력 체크
    insufficient_params = []
    if value_obj.user_type is None:
        insufficient_params.append(ValidationErrorStrs.user_type_required)
    if value_obj.username is None:
        insufficient_params.append(ValidationErrorStrs.username_required)
    if value_obj.phone is None:
        insufficient_params.append(ValidationErrorStrs.phone_required)
    if value_obj.email is None:
        insufficient_params.append(ValidationErrorStrs.email_required)
    if value_obj.password1 is None or value_obj.password2 is None:
        insufficient_params.append(ValidationErrorStrs.pw_required)
    if len(insufficient_params) > 0:
        return StandardErrorResponse(
            detail=insufficient_params,
            code="parameter_insufficient",
            status=status.HTTP_400_BAD_REQUEST,
        )

    # 이메일 형식 체크
    email_validation_result = validate_email(value_obj.email)
    if isinstance(email_validation_result, StandardErrorResponse):
        return email_validation_result

    # 비밀번호 일치 체크
    password_equality_validation_result = validate_password_equality(
        value_obj.password1, value_obj.password2
    )
    if isinstance(password_equality_validation_result, StandardErrorResponse):
        return password_equality_validation_result

    # 비밀번호 최소 길이 / 복잡성(너무 일상적인지 & 숫자로만 되어있는지) 체크
    password_format_validation_result = validate_password_format(
        value_obj.password1
    )
    if isinstance(password_format_validation_result, StandardErrorResponse):
        return password_format_validation_result

    # 모든 체크를 통과하면 None을 리턴
    return None


def returnUserAuthFailedError() -> StandardErrorResponse:
    return StandardErrorResponse(
        detail=[ValidationErrorStrs.user_auth_failed],
        code="user_authentication_failed",
        status=status.HTTP_401_UNAUTHORIZED,
    )


def validate_login(
    value_obj: LoginValidationValues,
) -> Optional[StandardErrorResponse]:
    # 필수항목 미입력 체크
    insufficient_params = []
    if value_obj.phone is None:
        insufficient_params.append(ValidationErrorStrs.phone_required)
    if value_obj.password is None:
        insufficient_params.append(ValidationErrorStrs.pw_required)
    if len(insufficient_params) > 0:
        return StandardErrorResponse(
            detail=insufficient_params,
            code="parameter_insufficient",
            status=status.HTTP_400_BAD_REQUEST,
        )

    # 위의 모든 체크를 통과했다면 None을 리턴
    return None


def is_user_code_exist(user_code):
    """
    user code가 이미 존재하는지 체크하는 함수
    """
    from .models import User

    users = User.objects.filter(user_code=user_code)
    if users.exists():
        return True
    else:
        return False


def generate_user_code(user_type):
    """
    유저 타입과 uuid를 이용해서 unique한 user code를 생성하는 함수
    유저 초기 생성(createsuperuser 등)에서는 UserModel을 추가할 수 없기 떄문에
    DB단의 중복체크 없이 생성한다.
    """
    uuid_str = uuid.uuid4().hex[:6].upper()
    user_code = str(user_type) + uuid_str

    return user_code


def generate_unique_user_code(user_type):
    """
    유저 타입과 uuid를 이용해서 unique한 user code를 생성하는 함수
    유저 타입 + uuid로 동일한 값이 나왔을 경우 (collision) 새로운 uuid를 구하여
    유저 타입 + uuid값을 새로 만든다.
    """
    user_code = generate_user_code(user_type)

    if is_user_code_exist(user_code) is True:
        return generate_unique_user_code(user_type)
    else:
        return user_code


class CustomPageNumberPagination(PageNumberPagination):
    page_size_query_param = "size"  # items per page


def returnSocialAuthFailedError() -> StandardErrorResponse:
    return StandardErrorResponse(
        detail=[ValidationErrorStrs.user_social_auth_failed],
        code="user_authentication_failed",
        status=status.HTTP_401_UNAUTHORIZED,
    )


def returnSocialAuthCheckFailedError() -> StandardErrorResponse:
    return StandardErrorResponse(
        detail=[ValidationErrorStrs.user_social_auth_check_failed],
        code="user_authentication_check_failed",
        status=status.HTTP_401_UNAUTHORIZED,
    )


def is_user_code_exist(user_code):
    """
    user code가 이미 존재하는지 체크하는 함수
    """
    from .models import User

    users = User.objects.filter(user_code=user_code)
    if users.exists():
        return True
    else:
        return False


def generate_user_code(user_type):
    """
    유저 타입과 uuid를 이용해서 unique한 user code를 생성하는 함수
    유저 초기 생성(createsuperuser 등)에서는 UserModel을 추가할 수 없기 떄문에
    DB단의 중복체크 없이 생성한다.
    """
    uuid_str = uuid.uuid4().hex[:6].upper()
    user_code = str(user_type) + uuid_str

    return user_code


def generate_unique_user_code(user_type):
    """
    유저 타입과 uuid를 이용해서 unique한 user code를 생성하는 함수
    유저 타입 + uuid로 동일한 값이 나왔을 경우 (collision) 새로운 uuid를 구하여
    유저 타입 + uuid값을 새로 만든다.
    """
    user_code = generate_user_code(user_type)

    if is_user_code_exist(user_code) is True:
        return generate_unique_user_code(user_type)
    else:
        return user_code


def is_first_login(user):
    """
    유저가 최초로그인인지 여부를 반환하는 함수

    - 가입과 로그인 시점의 차이가 1초 이내면 최초 로그인으로 간주
    - 추가적으로 last_login값이 None인 경우에도 최초 로그인으로 간주
    """
    if user.last_login is None:
        return True

    time_diff = user.last_login - user.date_joined
    return time_diff < datetime.timedelta(seconds=1)
