"""doc_schemas 모듈 설명

각 app별로 doc_schemas.py 모듈을 포함하여 해당 모듈내에서
변수로 각 API에 대한 request_body, response를 정의

정의된 값들은 views.py 내에서 각 API 상단에 데코레이터로 swagger / redoc 문서화에 필요한
request_body, response에 할당하여 사용
"""
from drf_yasg import openapi
from typing import Final

# /users/login API에서 문서화 (swagger / redoc)을 위해 사용하는 request_body & response
LOGIN_REQUEST_BODY: Final = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "phone": openapi.Schema(
            title="Phone Number",
            type=openapi.TYPE_STRING,
            description="`<= 20 characters`",
        ),
        "password": openapi.Schema(
            title="Password",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
    },
    required=["email", "password"],
)
LOGIN_RESPONSE: Final = {
    200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "token": openapi.Schema(
                title="Token",
                type=openapi.TYPE_STRING,
                description="Token string",
            ),
        },
    )
}

# /users/current API에서 문서화 (swagger / redoc)을 위해 사용하는 request_body & response
CURRENT_REQUEST_BODY: Final = None
CURRENT_RESPONSE: Final = {
    200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "phone": openapi.Schema(
                title="Phone Number",
                type=openapi.TYPE_STRING,
                description="`<= 20 characters`",
            ),
            "username": openapi.Schema(
                title="Username",
                type=openapi.TYPE_STRING,
                description="`<= 150 characters` `Nullable`",
            ),
            "group": openapi.Schema(
                title="group",
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_STRING),
                description="`<= 150 characters` `Nullable`",
            ),
        },
    )
}

# /users/registration API에서 문서화 (swagger / redoc)을 위해 사용하는 request_body & response
REGISTRATION_REQUEST_BODY: Final = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "phone": openapi.Schema(
            title="Phone Number",
            type=openapi.TYPE_STRING,
            description="`<= 20 characters`",
        ),
        "username": openapi.Schema(
            title="Username",
            type=openapi.TYPE_STRING,
            description="`<= 150 characters` `Nullable`",
        ),
        "password1": openapi.Schema(
            title="Password1",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
        "password2": openapi.Schema(
            title="Password2",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
    },
    required=["email", "password1", "password2"],
)
REGISTRATION_RESPONSE: Final = {
    200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "token": openapi.Schema(
                title="Token",
                type=openapi.TYPE_STRING,
                description="Token string",
            )
        },
    )
}

# /users/logout API에서 문서화 (swagger / redoc)을 위해 사용하는 request_body & response
USERAPP_LOGOUT_REQUEST_BODY: Final = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={},
)

USERAPP_LOGOUT_RESPONSE: Final = {
    205: openapi.Schema(type=openapi.TYPE_OBJECT, properties={})
}
# /users/current API(method: GET)에서 문서화 (swagger / redoc)을 위해 사용하는 request_body & response
INFO_REQUEST_BODY: Final = None
INFO_RESPONSE: Final = {
    200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "id": openapi.Schema(
                title="id",
                type=openapi.TYPE_INTEGER,
            ),
            "email": openapi.Schema(
                title="Email Address",
                type=openapi.TYPE_STRING,
                description="`<= 254 characters`",
            ),
            "username": openapi.Schema(
                title="Username",
                type=openapi.TYPE_STRING,
                description="`<= 30 characters`",
            ),
            "phone": openapi.Schema(
                title="phone",
                type=openapi.TYPE_STRING,
            ),
        },
    )
}
PASSWORD_CONFIRM_REQUEST_BODY: Final = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "password": openapi.Schema(
            title="Password",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
    },
)
PASSWORD_CONFIRM_RESPONSE: Final = {
    200: openapi.Schema(type=openapi.TYPE_OBJECT, properties={}),
}

UPDATE_PASSWORD_REQUEST_BODY: Final = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "before_password": openapi.Schema(
            title="BeforePassword",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
        "new_password1": openapi.Schema(
            title="NewPassword1",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
        "new_password2": openapi.Schema(
            title="NewPassword2",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
    },
)
UPDATE_PASSWORD_RESPONSE: Final = {
    200: openapi.Schema(type=openapi.TYPE_OBJECT, properties={}),
}

UPDATE_NICKNAME_REQUEST_BODY: Final = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "nickname": openapi.Schema(
            title="nickname",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
    },
)
UPDATE_NICKNAME_RESPONSE: Final = {
    200: openapi.Schema(type=openapi.TYPE_OBJECT, properties={}),
}

UPDATE_PHONE_REQUEST_BODY: Final = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "phone": openapi.Schema(
            title="phone",
            type=openapi.TYPE_STRING,
            description="`8 <= & <= 128 characters`",
        ),
    },
)
UPDATE_PHONE_RESPONSE: Final = {
    200: openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "token": openapi.Schema(
                title="token",
                type=openapi.TYPE_STRING,
                description="token",
            ),
            "user_type": openapi.Schema(
                title="user_type",
                type=openapi.TYPE_STRING,
                description="user_type",
            ),
        },
    ),
}

UPDATE_SHOP_REQUEST_BODY: Final = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        "shop_id": openapi.Schema(
            title="shop_id",
            type=openapi.TYPE_INTEGER,
        ),
    },
)
UPDATE_SHOP_RESPONSE: Final = {
    200: openapi.Schema(type=openapi.TYPE_OBJECT, properties={}),
}
