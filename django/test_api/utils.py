# test_api/utils.py (common utils)
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from drf_yasg.inspectors import SwaggerAutoSchema
from collections import OrderedDict
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import ValidationError, APIException

# 공용으로 사용할 Raise 및 Error 문구
DEFAULT_ERROR_MSGS_DICT = {
    "user_does_not_exist": _("사용자가 존재하지 않습니다."),
    "voucher_does_not_exist": _("이용권이 존재하지 않습니다."),
    "voucher_do_not_match": _("이용권이 일치하지 않습니다."),
    "pro_reservation_exist": _("프로의 예약이 존재합니다."),
    "room_reservation_exist": _("이용공간에 예약이 존재합니다."),
    "room_block_exist": _("이용공간이 블락되어 있는 시간입니다"),
    "pro_block_exist": _("프로가 블락되어 있는 시간입니다."),
    "pro_reservation_exist": _("프로의 예약이 존재합니다."),
}


class CustomPageNumberPagination(PageNumberPagination):
    page_size_query_param = "size"  # items per page


class StandardErrorResponse(Response):
    def __init__(self, detail, code: str, status: int):
        payload = {"detail": detail, "code": code}
        super().__init__(data=payload, status=status)


class StandardErrorRaise:
    def __init__(self, code, detail=None):
        self.code = code
        self.detail = DEFAULT_ERROR_MSGS_DICT.get(code)

    def set_raise_msg(self):
        payload = {"detail": [self.detail], "code": self.code}
        return payload


class UnprocessableEntityError(APIException):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    default_code = "unprocessable_entity"


class ConflictError(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_code = "value_duplicated"


class EntityTooLargeError(ValidationError):
    """
    413 Entity Too Large 오류를 리턴하기 위해
    DRF의 ValidationError를 상속받아 status code만 오버라이딩한 클래스
    """

    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


# ***************************************************************
# drf-yasg SWAGGER_SETTINGS에서 사용
# - read_only / write_only 필드가 doc에서 한번에 노출되지 않도록 하기 위함
# ***************************************************************
class ReadOnly:  # pragma: no cover
    def get_fields(self):
        new_fields = OrderedDict()
        for fieldName, field in super().get_fields().items():
            if not field.write_only:
                new_fields[fieldName] = field
        return new_fields


class BlankMeta:  # pragma: no cover
    pass


class WriteOnly:  # pragma: no cover
    def get_fields(self):
        new_fields = OrderedDict()
        for fieldName, field in super().get_fields().items():
            if not field.read_only:
                new_fields[fieldName] = field
        return new_fields


class ReadWriteAutoSchema(SwaggerAutoSchema):  # pragma: no cover
    def get_view_serializer(self):
        return self._convert_serializer(WriteOnly)

    def get_default_response_serializer(self):
        body_override = self._get_request_body_override()
        if body_override and body_override is not no_body:
            return body_override

        return self._convert_serializer(ReadOnly)

    def _convert_serializer(self, new_class):
        serializer = super().get_view_serializer()
        if not serializer:
            return serializer

        class CustomSerializer(new_class, serializer.__class__):
            class Meta(getattr(serializer.__class__, "Meta", BlankMeta)):
                ref_name = new_class.__name__ + serializer.__class__.__name__

        new_serializer = CustomSerializer(data=serializer.data)
        return new_serializer


class CustomErrorMsg:

    DEFAULT_ERROR_MSGS_DICT = {
        "required": _("필수 값 입니다."),
        "required_query_param": _("필수 값 입니다."),
        "does_not_exist": _("존재하지 않습니다."),
        "reservation_exists": _("이 시간에 예약이 이미 존재합니다."),
        "pro_exists": _("이 시간에 프로의 다른 일정이 이미 존재합니다."),
        "voucher_empty": _("사용할 수 있는 이용권이 없습니다."),
        "block_exists": _("일정이 블락되어 있는 시간입니다."),
        "user_voucher_do_not_match": _("이용권이 일치하지 않습니다."),
        "impossible_date": _("예약 불가능한 날짜입니다."),
        "price_do_not_match": _("결제 가격이 일치하지 않습니다."),
        "reservation_exists": _("예약이 존재하여 블락이 불가능합니다."),
        "end_date_not_match": _("유효기간 만료일이 오늘날짜보다 전입니다."),
    }

    def __init__(self, error_msg_dict=None):
        self.error_msg_dict = error_msg_dict

    def set_error_msg_dict(self, param, value, key, additional_value=None):

        msg_str = self.DEFAULT_ERROR_MSGS_DICT.get(key)
        if (
            key == "does_not_exist"
            or key == "not_include_type_at_brand"
            or key == "can_not_update_with_id"
        ):
            msg_str = msg_str.format(pk_value=value)
        elif key == "at_least_required" or key == "only_one_required":
            msg_str = msg_str.format(param=param)
        elif key == "exceed_file_size_limit":
            msg_str = msg_str.format(additional_value=additional_value)

        if self.error_msg_dict is None:
            self.error_msg_dict = {param: [msg_str]}
        else:
            if param in self.error_msg_dict:
                if isinstance(self.error_msg_dict[param], list):
                    self.error_msg_dict[param].append(msg_str)
                else:  # 키값이 리스트가 아닌 경우에 대한 예외처리
                    self.error_msg_dict[param] = msg_str
            else:
                self.error_msg_dict[param] = [msg_str]

    def get_error_msg_dict(self):
        return self.error_msg_dict

    def get_error_msg(self, key):
        return self.DEFAULT_ERROR_MSGS_DICT.get(key)
