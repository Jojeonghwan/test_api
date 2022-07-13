# users/urls.py
from django.urls import include, path
from users import views
from .views import (
    AdminWebLoginView,
    AdminWebLogoutView,
    KakaoAppleSignUpView,
    kakao_temp_login,
    kakao_temp_login_callback,
    UserWithdraw,
    KakaoAppleSignUpCheckView,
)
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

urlpatterns = [
    path("current/", views.current, name="current-user"),
    path("app-login/", views.app_login, name="login"),
    path("app-logout/", views.app_logout, name="logout"),
    path("app-user-info/", views.app_user_info, name="user-info"),
    path("registration/", views.registration, name="registration"),
    path(
        "app-password/confirm/",
        views.password_confirm,
        name="password-confirm",
    ),
    path(
        "app-password/update/",
        views.password_update,
        name="password-update",
    ),
    path("admin-login/", AdminWebLoginView.as_view(), name="admin-web-login"),
    # JWT Token refresh용 API는 simplejwt의 View를 그대로 사용
    path(
        "admin-login/refresh/",
        TokenRefreshView.as_view(),
        name="token_refresh",
    ),
    path(
        "admin-logout/", AdminWebLogoutView.as_view(), name="admin-web-logout"
    ),
    path(
        "app-nickname/update/",
        views.nickname_update,
        name="nickname-update",
    ),
    path(
        "app-phone/update/",
        views.phone_update,
        name="phone-update",
    ),
    path(
        "app-shop/update/",
        views.shop_update,
        name="shop-update",
    ),
    path(
        "app/kakao-apple-login-check/",
        KakaoAppleSignUpCheckView.as_view(),
        name="kakao-apple-login-check",
    ),
    path(
        "app/kakao-apple-login/",
        KakaoAppleSignUpView.as_view(),
        name="kakao-apple-login",
    ),
    path(
        "kakao-temp-login/",
        kakao_temp_login,
        name="kakao-temp-login",
    ),
    path(
        "kakao-temp-login/callback",
        kakao_temp_login_callback,
        name="kakao-temp-login-callback",
    ),
    path(
        "userwithdraw/<int:pk>/", UserWithdraw.as_view(), name="user_withdraw"
    ),
]
