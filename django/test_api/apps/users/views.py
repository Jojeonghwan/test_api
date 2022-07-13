from django.shortcuts import render, redirect
from django.urls import reverse
from django.db import IntegrityError
from .models import User, SocialLoginLink, SocialLoginType
from django.contrib.auth.models import Group
from .serializers import (
    AdminWebLoginResponseSerializer,
    AdminWebLoginSerializer,
    AdminWebLogoutSerializer,
    KakaoAppleSignUpRequestSerializer,
    UserRegistrationDoneSerializer,
    KakaoAppleSignUpCheckRequestSerializer,
    KakaoAppleSignUpCheckResponseSerializer,
)
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from drf_yasg.utils import swagger_auto_schema
from datetime import datetime
from test_api.utils import StandardErrorResponse
from .utils import (
    RegistrationValidationValues,
    ValidationErrorStrs,
    validate_registration,
    returnUserAuthFailedError,
    returnSocialAuthFailedError,
    returnSocialAuthCheckFailedError,
    generate_unique_user_code,
    is_first_login,
)
from users import doc_schemas as ds
import hashlib
from test_api.utils import (
    CustomErrorMsg,
)
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.utils.decorators import method_decorator
import requests
from django.db import transaction
import os
from urllib.parse import unquote
import hashlib


@swagger_auto_schema(
    method="post",
    request_body=ds.LOGIN_REQUEST_BODY,
    responses=ds.LOGIN_RESPONSE,
    tags=["[userapp] users"],
)
@api_view(["POST"])
@permission_classes((permissions.AllowAny,))
def app_login(request):
    """
    post:커스텀 유저 로그인 API

    ---
    - HTTP Header에 api-key Token 필요
      key: Authorization, value: Token [토큰값] (예시: Authorization: Token c5a4e25a7c5d8dc545c8d10740bfe655429c129b)

    """
    phone = request.data.get("phone")
    password = request.data.get("password")

    # 이메일 체크를 사용하지 않아 주석 처리
    # Validation check
    # validation_result = validate_login(LoginValidationValues(request))
    # if isinstance(validation_result, StandardErrorResponse):
    #     return validation_result

    # 유저 타입 체크가 완료되면 타입별로 유저 정보를 확인하여 로그인 처리
    try:
        user = User.objects.get(phone=phone, user_type="U")
        is_password_valid = user.check_password(password)
    except User.DoesNotExist:
        return returnUserAuthFailedError()
    else:
        if not is_password_valid:
            return returnUserAuthFailedError()

        # 해당 유저의 토큰이 존재하면 그대로 리턴, 없으면 새로 만들어 리턴
        try:
            token_obj = Token.objects.create(user=user)
        except IntegrityError:
            token_obj = Token.objects.get(user=user)
        token = token_obj.key

        # 유저의 last_login값 업데이트
        user.last_login = datetime.now()
        user.save(update_fields=["last_login"])

    return Response({"token": token})


@swagger_auto_schema(
    method="post",
    request_body=ds.USERAPP_LOGOUT_REQUEST_BODY,
    responses=ds.USERAPP_LOGOUT_RESPONSE,
    tags=["[userapp] users"],
)
@api_view(["POST"])
@permission_classes((permissions.IsAuthenticated,))
def app_logout(request):
    """
    post: 회원앱 커스텀 유저 로그아웃 API (토큰방식)

    - HTTP Header에 api-key Token 필요
      key: Authorization, value: Token [토큰값] (예시: Authorization: Token c5a4e25a7c5d8dc545c8d10740bfe655429c129b)

    """

    try:
        token = Token.objects.get(user=request.user)
        token.delete()
    except Token.DoesNotExist:
        return Response(
            {
                "token": ["does_not_exist"],
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response(status=status.HTTP_205_RESET_CONTENT)


@swagger_auto_schema(
    method="get",
    request_body=ds.INFO_REQUEST_BODY,
    responses=ds.INFO_RESPONSE,
    tags=["[userapp] users"],
)
@api_view(["GET"])
@permission_classes((permissions.IsAuthenticated,))
def app_user_info(request):
    """
    get: 현재 로그인한 계정의 정보를 조회하는 API

    - HTTP Header에 api-key Token 필요
      key: Authorization, value: Token [토큰값] (예시: Authorization: Token c5a4e25a7c5d8dc545c8d10740bfe655429c129b)

    """
    if request.method == "GET":

        return Response(
            {
                "id": request.user.id,
                "user_name": request.user.username,
                "email": request.user.email,
                "phone": request.user.phone,
            }
        )


@swagger_auto_schema(
    method="get",
    request_body=ds.CURRENT_REQUEST_BODY,
    responses=ds.CURRENT_RESPONSE,
)
@api_view(["GET"])
@permission_classes((permissions.IsAuthenticated,))
def current(request):
    """
    get:현재 로그인한 유저의 정보를 조회하는 API

    ---
    ## API URL: `/users/current/`
    """

    groups = Group.objects.filter(user=request.user.id)

    group_arr = []
    if groups.exists():
        for group in groups:
            group_arr.append(group.name)

    return Response(
        {
            "phone": request.user.phone,
            "username": request.user.username,
            "group": group_arr,
        }
    )


@swagger_auto_schema(
    method="post",
    request_body=ds.REGISTRATION_REQUEST_BODY,
    responses=ds.REGISTRATION_RESPONSE,
)
@api_view(["POST"])
@permission_classes((permissions.AllowAny,))
def registration(request):
    """
    post: 유저 가입 처리를 하는 API

    ---
    ## API URL: `/users/registration/`
    """
    phone = request.data.get("phone")
    username = request.data.get("username")  # 유저명은 None도 허용. 즉, optional
    password1 = request.data.get("password1")
    # password2 = request.data.get('password2')  # password2는 validation에서만 사용하므로 주석처리

    # 기본 Validation check
    validation_result = validate_registration(RegistrationValidationValues(request))
    if isinstance(validation_result, StandardErrorResponse):
        return validation_result

    # Validation check를 모두 통확하면 user_type에 따른 중복검사 진행
    users = User.objects.filter(phone=phone)

    hash_text = phone + username
    sha1 = hashlib.new("sha1")
    sha1.update(hash_text.encode("utf-8"))
    user_code = sha1.hexdigest()

    if users.count() > 0:
        return StandardErrorResponse(
            detail=ValidationErrorStrs.email_exist,
            code="email_already_exists",
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # user_type에 동일한 전화번호가 없다면 회원 등록(create) 진행
    user = User.objects.create(
        phone=phone, username=username, status_id=4, user_code=user_code
    )

    user.set_password(password1)
    user.save(update_fields=["password"])
    try:
        token_obj = Token.objects.create(user=user)
    except IntegrityError:
        token_obj = Token.objects.get(user=user)
    token = token_obj.key

    return Response({"token": token})


@swagger_auto_schema(
    method="post",
    request_body=ds.PASSWORD_CONFIRM_REQUEST_BODY,
    responses=ds.PASSWORD_CONFIRM_RESPONSE,
    tags=["[userapp] users"],
)
@api_view(["POST"])
@permission_classes((permissions.IsAuthenticated,))
def password_confirm(request):
    """
    post: 비밀번호 확인 API

    - HTTP Header에 api-key Token 필요
        key: Authorization, value: Token [토큰값] (예시: Authorization: Token c5a4e25a7c5d8dc545c8d10740bfe655429c129b)

    """
    custom_user = request.user
    password = request.data.get("password", None)

    if not password:
        cem = CustomErrorMsg()
        cem.set_error_msg_dict(
            param="password",
            value=None,
            key="required",
        )
        raise ValidationError(cem.get_error_msg_dict())

    if custom_user.check_password(password):
        return Response(status=status.HTTP_200_OK)
    else:
        return Response(
            {
                "password": "틀린 비밀번호 입니다.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@swagger_auto_schema(
    method="patch",
    request_body=ds.UPDATE_PASSWORD_REQUEST_BODY,
    responses=ds.UPDATE_PASSWORD_RESPONSE,
    tags=["[userapp] users"],
)
@api_view(["PATCH"])
@permission_classes((permissions.AllowAny,))
def password_update(request):
    """
    patch: 비밀번호 변경 API

    - HTTP Header에 api-key Token 필요
        key: Authorization, value: Token [토큰값] (예시: Authorization: Token c5a4e25a7c5d8dc545c8d10740bfe655429c129b)

    """

    custom_user_id = request.user.id
    before_password = request.data.get("before_password", None)
    new_password1 = request.data.get("new_password1", None)
    new_password2 = request.data.get("new_password2", None)

    if not before_password:
        cem = CustomErrorMsg()
        cem.set_error_msg_dict(
            param="before_password",
            value=None,
            key="required",
        )
        raise ValidationError(cem.get_error_msg_dict())

    if not new_password1:
        cem = CustomErrorMsg()
        cem.set_error_msg_dict(
            param="new_password1",
            value=None,
            key="required",
        )
        raise ValidationError(cem.get_error_msg_dict())
    if not new_password2:
        cem = CustomErrorMsg()
        cem.set_error_msg_dict(
            param="new_password2",
            value=None,
            key="required",
        )
        raise ValidationError(cem.get_error_msg_dict())

    if new_password1 != new_password2:
        return Response(
            {
                "password": "두 비밀번호가 서로 다릅니다.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        user = User.objects.get(id=custom_user_id)
    except User.DoesNotExist:
        return Response(
            {
                "password": "존재하지 않은 사용자입니다.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    if user.check_password(before_password):
        user.set_password(new_password1)
        user.save()
        return Response(status=status.HTTP_200_OK)
    else:
        return Response(
            {
                "password": "틀린 비밀번호 입니다.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


class AdminWebLoginView(APIView):
    """
    post: 어드민 Web 로그인 API

    - 어드민 Web은 JWT를 사용
    - 어드민 Web에서의 user_type은 `A` (코드내에서 처리)
    """

    permission_classes = [permissions.AllowAny]

    @method_decorator(
        name="post",
        decorator=swagger_auto_schema(
            request_body=AdminWebLoginSerializer,
            responses={200: AdminWebLoginResponseSerializer},
        ),
    )
    def post(self, request):
        # Serializer에서 기본 validtion 처리를 하고 문제가 있는 경우 exception 발생 처리
        serializer = AdminWebLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # Serizlier를 통해 validation이 통과된 데이터 값 획득
        phone = serializer.data["phone"]
        password = serializer.data["password"]

        try:
            user = User.objects.get(user_type="A", phone=phone)
            is_password_valid = user.check_password(password)
        except User.DoesNotExist:
            return returnUserAuthFailedError()

        if not is_password_valid:
            return returnUserAuthFailedError()

        # JWT 토큰 수동 생성
        refresh = RefreshToken.for_user(user)
        jwt = {"refresh": str(refresh), "access": str(refresh.access_token)}
        return Response(AdminWebLoginResponseSerializer(jwt).data)


class AdminWebLogoutView(APIView):
    """
    post: 어드민 Web 로그아웃 API

    해당 유저의 refresh 토큰을 post parameter로 넘겨야하며
    서버단에서 해당 토큰을 만료기한과 상관없이 블락 처리하게 함.
    """

    permission_classes = [permissions.AllowAny]

    @method_decorator(
        name="post",
        decorator=swagger_auto_schema(
            request_body=AdminWebLogoutSerializer,
            responses={205: ""},
        ),
    )
    def post(self, request):
        serializer = AdminWebLogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.data["refresh"]
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            # Refresh 토큰이 잘못된 상태 혹은 만료된 상태인 경우에는
            # 해당 토큰을 블록시키는 것이 의미가 없으므로 정상처리된 것과 동일한 Reponse로 처리
            return Response(status=status.HTTP_205_RESET_CONTENT)


@swagger_auto_schema(
    method="patch",
    request_body=ds.UPDATE_NICKNAME_REQUEST_BODY,
    responses=ds.UPDATE_NICKNAME_RESPONSE,
    tags=["[userapp] users"],
)
@api_view(["PATCH"])
@permission_classes((permissions.IsAuthenticated,))
def nickname_update(request):
    """
    patch: 닉네임 변경 API

    - HTTP Header에 api-key Token 필요
        key: Authorization, value: Token [토큰값] (예시: Authorization: Token c5a4e25a7c5d8dc545c8d10740bfe655429c129b)

    """

    custom_user_id = request.user.id
    nickname = request.data.get("nickname", None)

    try:
        user = User.objects.get(id=custom_user_id)
    except User.DoesNotExist:
        return StandardErrorResponse(
            detail=["존재하지 않는 사용자입니다."],
            code="does_not_exist",
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        user_info = UserInfo.objects.get(user_account_id=user.id)
    except User.DoesNotExist:
        return StandardErrorResponse(
            detail=["존재하지 않는 사용자입니다."],
            code="does_not_exist",
            status=status.HTTP_400_BAD_REQUEST,
        )
    user.username = nickname
    user_info.name = nickname
    user.save(update_fields=["username"])
    user_info.save(update_fields=["name"])
    return Response(status=status.HTTP_200_OK)


@swagger_auto_schema(
    method="patch",
    request_body=ds.UPDATE_PHONE_REQUEST_BODY,
    responses=ds.UPDATE_PHONE_RESPONSE,
    tags=["[userapp] users"],
)
@api_view(["PATCH"])
@permission_classes((permissions.IsAuthenticated,))
def phone_update(request):
    """
    patch: 핸드폰 번호 변경 API

    - HTTP Header에 api-key Token 필요
        - key: Authorization, value: Token [토큰값] (예시: Authorization: Token c5a4e25a7c5d8dc545c8d10740bfe655429c129b)
    - user_tpye
        - connect: 신규 소셜 가입으로 인한 연동된 기존 고객 (홈화면으로 이동)
        - old: 신규 소셜 가입완료 됐거나 기존 고객 소셜 연동 된후 번호 변경 (다음스텝으로 이동)

    - 신규든 기존 고객이든 토큰값 변경으로 Response로 주어진 토큰값으로 변경 필요
    """

    custom_user_id = request.user.id
    phone = request.data.get("phone", None)

    try:
        user = User.objects.get(id=custom_user_id)
    except User.DoesNotExist:
        return StandardErrorResponse(
            detail=["존재하지 않는 사용자입니다."],
            code="user_does_not_exist",
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        user_info = UserInfo.objects.get(user_account_id=user.id)
    except User.DoesNotExist:
        return StandardErrorResponse(
            detail=["user_존재하지 않는 사용자입니다."],
            code="does_not_exist",
            status=status.HTTP_400_BAD_REQUEST,
        )
    users = User.objects.filter(phone=phone, user_type="U")
    real_user = User.objects.none()
    user_type = ""
    if user.phone is None and users.exists():
        connect_user = users.first()
        connect_social_login_link = SocialLoginLink.objects.get(user_id=user.id)
        try:
            connect_social_login_link = SocialLoginLink.objects.get(user_id=user.id)
        except SocialLoginLink.DoesNotExist:
            return StandardErrorResponse(
                detail=["존재하지 않는 소셜 사용자입니다."],
                code="social_does_not_exist",
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            connect_user_info = UserInfo.objects.get(user_account_id=connect_user.id)
        except UserInfo.DoesNotExist:
            return StandardErrorResponse(
                detail=["존재하지 않는 사용자입니다."],
                code="social_does_not_exist",
                status=status.HTTP_400_BAD_REQUEST,
            )
        connect_social_login_link.user = connect_user
        connect_social_login_link.save(update_fields=["user"])
        connect_user_info.user_account = connect_user
        connect_user_info.save(update_fields=["user_account"])
        try:
            user_info = UserInfo.objects.get(user_account_id=user.id)
            user_info.delete()
        except UserInfo.DoesNotExist:
            return StandardErrorResponse(
                detail=["존재하지 않는 사용자입니다."],
                code="user_does_not_exist",
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = Token.objects.get(user=request.user)
            token.delete()
        except Token.DoesNotExist:
            return StandardErrorResponse(
                detail=["토큰이 존재하지 않습니다."],
                code="does_not_token",
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.delete()

        user_type = "connect"
        real_user = connect_user
    else:
        user.phone = phone
        user_info.phone = phone
        user.save(update_fields=["phone"])
        user_info.save(update_fields=["phone"])
        user_type = "old"
        real_user = user
    try:
        token_obj = Token.objects.create(user=real_user)
    except IntegrityError:
        try:
            token_obj = Token.objects.get(user=real_user)
        except Token.DoesNotExist:
            return StandardErrorResponse(
                detail=["토큰이 존재하지 않습니다."],
                code="does_not_token",
                status=status.HTTP_400_BAD_REQUEST,
            )
    data = {
        "token": token_obj.key,
        "user_type": user_type,
    }
    return Response(data, status=status.HTTP_200_OK)


@swagger_auto_schema(
    method="patch",
    request_body=ds.UPDATE_SHOP_REQUEST_BODY,
    responses=ds.UPDATE_SHOP_RESPONSE,
    tags=["[userapp] users"],
)
@api_view(["PATCH"])
@permission_classes((permissions.AllowAny,))
def shop_update(request):
    """
    patch: 주 이용 지점 변경 API

    - HTTP Header에 api-key Token 필요
        key: Authorization, value: Token [토큰값] (예시: Authorization: Token c5a4e25a7c5d8dc545c8d10740bfe655429c129b)

    """

    custom_user_id = request.user.id
    shop_id = request.data.get("shop_id", None)

    try:
        user = User.objects.get(id=custom_user_id)
    except User.DoesNotExist:
        return StandardErrorResponse(
            detail=["존재하지 않는 사용자입니다."],
            code="does_not_exist",
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        user_info = UserInfo.objects.get(user_account_id=user.id)
    except User.DoesNotExist:
        return StandardErrorResponse(
            detail=["존재하지 않는 사용자입니다."],
            code="does_not_exist",
            status=status.HTTP_400_BAD_REQUEST,
        )
    if user_info.shop_id is not None:
        return StandardErrorResponse(
            detail=["주 이용 지점이 이미 등록되어 있는 사용자 입니다."],
            code="shop_exist",
            status=status.HTTP_400_BAD_REQUEST,
        )
    user_info.shop_id = shop_id
    user_info.save(update_fields=["shop_id"])
    return Response(status=status.HTTP_200_OK)


class KakaoAppleSignUpCheckView(APIView):
    """
    post: 카카오 및 애플 로그인 체크 API

    - type 파라미터 필수 (type: K, A)
    - credential 파라미터 필수 (kakao, apple API 인증 완료후 받은 access_token(Kakao) or user(apple))값 전달
    """

    permission_classes = [permissions.AllowAny]

    @method_decorator(
        name="post",
        decorator=swagger_auto_schema(
            request_body=KakaoAppleSignUpCheckRequestSerializer,
            responses={200: KakaoAppleSignUpCheckResponseSerializer},
            tags=["[userapp] users"],
        ),
    )
    def post(self, request):
        serializer = KakaoAppleSignUpCheckRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        social_data = serializer.data
        social_type = social_data["social_type"]
        credential = social_data["credential"]

        if social_type == SocialLoginType.KAKAO.value:
            access_token = credential

            url = "https://kapi.kakao.com/v2/user/me"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
            }
            res = requests.get(url, headers=headers)

            if res.status_code != 200:
                return returnSocialAuthCheckFailedError()

            res = res.json()
            kakao_id = res.get("id", None)

            if kakao_id is None:
                return returnSocialAuthCheckFailedError()

            social_id = kakao_id

        elif social_type == SocialLoginType.APPLE.value:
            # credential is apple user id
            social_id = credential

        social_login_link = SocialLoginLink.objects.filter(
            social_type=social_type,
            social_id=social_id,
        )

        return Response(
            {
                "sign_up_check": social_login_link.exists(),
            }
        )


class KakaoAppleSignUpView(APIView):
    """
    post: 카카오 및 애플 로그인 API

    - type 파라미터 필수 (type: K, A)
    - credential 파라미터 필수 (kakao, apple API 인증 완료후 받은 access_token(Kakao) or user(apple))값 전달
    - username 파라미터 필수
    - email 파라미터 필수
    - advertising_check 파라미터 필수
    """

    permission_classes = [permissions.AllowAny]

    @method_decorator(
        name="post",
        decorator=swagger_auto_schema(
            request_body=KakaoAppleSignUpRequestSerializer,
            responses={200: UserRegistrationDoneSerializer},
            tags=["[userapp] users"],
        ),
    )
    def post(self, request):
        serializer = KakaoAppleSignUpRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        social_data = serializer.data
        user_type = "U"
        social_type = social_data["social_type"]
        credential = social_data["credential"]
        username = social_data["username"]
        email = social_data["email"]
        advertising_check = social_data["advertising_check"]

        if social_type == SocialLoginType.KAKAO.value:
            access_token = credential

            url = "https://kapi.kakao.com/v2/user/me"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
            }
            res = requests.get(url, headers=headers)

            if res.status_code != 200:
                return returnSocialAuthFailedError()

            res = res.json()
            kakao_id = res.get("id", None)
            kakao_name = res["kakao_account"].get("name", None)
            kakao_email = res["kakao_account"].get("email", None)

            # url = "https://kapi.kakao.com/v1/user/access_token_info"
            # headers = {
            #     "Authorization": f"Bearer {access_token}",
            #     "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
            # }
            # res = requests.get(url, headers=headers)
            # if res.status_code != 200:
            #     return returnSocialAuthFailedError()

            # res = res.json()
            # kakao_id = res.get("id", None)
            if kakao_id is None:
                return returnSocialAuthFailedError()

            social_id = kakao_id

        elif social_type == SocialLoginType.APPLE.value:
            # credential is apple user id
            social_id = credential
        with transaction.atomic():
            social_login_link, created = SocialLoginLink.objects.get_or_create(
                social_type=social_type,
                social_id=social_id,
            )

            if created is True:
                if social_type == SocialLoginType.KAKAO.value:
                    username = kakao_name
                    email = kakao_email
                user = User.objects.create(
                    user_type=user_type,
                    username=username,
                    user_code=generate_unique_user_code(user_type),
                )
                social_login_link.user = user
                social_login_link.social_email = email
                social_login_link.save(update_fields=["user", "social_email"])
                UserInfo.objects.create(
                    name=username,
                    status_id=12,
                    user_account=user,
                    advertising_check=advertising_check,
                )

            else:
                user = User.objects.get(id=social_login_link.user_id)
        try:
            token_obj = Token.objects.create(user=user)
        except IntegrityError:
            try:
                token_obj = Token.objects.get(user=user)
            except Token.DoesNotExist:
                return StandardErrorResponse(
                    detail=["토큰이 존재하지 않습니다."],
                    code="does_not_token",
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # 유저의 last_login값 업데이트
        user.last_login = datetime.now()
        user.save(update_fields=["last_login"])

        # 최초 로그인 여부 확인
        is_first_login_value = is_first_login(user)

        return Response(
            {
                "id": user.id,
                "token": token_obj.key,
                "is_first_login": is_first_login_value,
            }
        )


# redirect_uri = "http://localhost:8000/users/kakao-temp-login/callback"
client_id = os.environ.get("KAKAO_REST_API_KEY")
client_secret = os.environ.get("KAKAO_CLIENT_SECRET")


def kakao_temp_login(request):
    redirect_uri = reverse("kakao-temp-login-callback")
    redirect_uri = request.build_absolute_uri(redirect_uri)

    return redirect(
        f"https://kauth.kakao.com/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope=name,account_email"
    )


def kakao_temp_login_callback(request):
    redirect_uri = reverse("kakao-temp-login-callback")
    redirect_uri = request.build_absolute_uri(redirect_uri)

    code = request.GET.get("code")
    url = "https://kauth.kakao.com/oauth/token"
    headers = {
        "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
    }
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "redirectUri": redirect_uri,
        "code": code,
    }

    res = requests.post(url, data=data, headers=headers)

    if res.status_code != 200:
        return render(
            request,
            "kakao-login.html",
            {"error": "로그인에 문제가 발생했습니다.\n문제가 지속되면 고객센터로 문의해주시기 바랍니다."},
        )

    res = res.json()
    access_token = res.get("access_token")
    url = "https://kapi.kakao.com/v2/user/me"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-type": "application/x-www-form-urlencoded;charset=utf-8",
    }
    res = requests.get(url, headers=headers)

    if res.status_code != 200:
        return render(
            request,
            "kakao-login.html",
            {"error": "로그인에 문제가 발생했습니다.\n문제가 지속되면 고객센터로 문의해주시기 바랍니다."},
        )

    res = res.json()
    name = res["kakao_account"].get("name", "null")
    email = res["kakao_account"].get("email", "null")
    return render(
        request,
        "kakao-login.html",
        {"credential": access_token, "name": name, "email": email},
    )


class UserWithdraw(APIView):
    """
    delete: 유저 회원 탈퇴

    - 회원 탈퇴 처리
    """

    permission_classes = [permissions.IsAuthenticated]

    @method_decorator(
        name="delete",
        decorator=swagger_auto_schema(
            request_body=None,
            responses={200: ""},
        ),
    )
    @transaction.atomic()
    def delete(self, request, pk, format=None):
        user = self.request.user
        user_info = UserInfo.objects.get(user_account_id=user.id)
        social_logins = SocialLoginLink.objects.filter(user_id=user.id)
        if not user_info.id == pk:
            return Response(
                {
                    "pk": ["does_not_match"],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        blake = hashlib.blake2b(digest_size=5)
        if user.username is not None:
            blake.update(user.username.encode())
            user.username = blake.hexdigest()

        if user.phone is not None:
            blake.update(
                user.phone.encode()
                + user.date_joined.strftime("%m/%d/%Y, %H:%M:%S").encode()
            )
            user.phone = blake.hexdigest()

        if user.email is not None:
            blake.update(user.email.encode())
            user.email = blake.hexdigest()
        user.status_id = 52

        user.save()

        for social_login in social_logins:
            blake.update(social_login.social_id.encode())
            social_login.social_id = blake.hexdigest()

            if social_login.social_email is not None:
                blake.update(social_login.social_email.encode())
                social_login.social_email = blake.hexdigest()

            social_login.save()

        if user_info.name is not None:
            blake.update(user_info.name.encode())
            user_info.name = blake.hexdigest()

        if user_info.phone is not None:
            blake.update(
                user_info.phone.encode()
                + user_info.created_at.strftime("%m/%d/%Y, %H:%M:%S").encode()
            )
            user_info.phone = blake.hexdigest()

        user_info.birth = datetime(9999, 12, 31)
        if user_info.email is not None:
            blake.update(user_info.email.encode())
            user_info.email = blake.hexdigest()

        if user_info.address is not None:
            blake.update(user_info.address.encode())
            user_info.address = blake.hexdigest()

        if user_info.detail_address is not None:
            blake.update(user_info.detail_address.encode())
            user_info.detail_address = blake.hexdigest()

        user_info.deleted_at = datetime.now()

        user_info.save()
        try:
            token = Token.objects.get(user=request.user)
            token.delete()
        except Token.DoesNotExist:
            return Response(
                {
                    "token": ["does_not_exist"],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(status=status.HTTP_200_OK)
