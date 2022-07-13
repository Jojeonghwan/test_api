from unittest.mock import seal
from jmespath import search
from rest_framework import serializers
from users.models import SocialLoginType


class KakaoAppleSignUpRequestSerializer(serializers.Serializer):
    social_type = serializers.ChoiceField(choices=SocialLoginType.choices)
    credential = serializers.CharField()
    username = serializers.CharField(
        allow_blank=True, allow_null=True, required=False
    )
    email = serializers.CharField(
        allow_blank=True, allow_null=True, required=False
    )
    advertising_check = serializers.BooleanField(default=False)


class UserRegistrationDoneSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    token = serializers.CharField()
    is_first_login = serializers.BooleanField()


class AdminWebLoginSerializer(serializers.Serializer):
    phone = serializers.CharField()
    password = serializers.CharField()


class AdminWebLoginResponseSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()


class AdminWebLogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class AdminWebLogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class KakaoAppleSignUpCheckRequestSerializer(serializers.Serializer):
    social_type = serializers.ChoiceField(choices=SocialLoginType.choices)
    credential = serializers.CharField()


class KakaoAppleSignUpCheckResponseSerializer(serializers.Serializer):
    sign_up_check = serializers.BooleanField()
