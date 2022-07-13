# users/forms.py
# CustomUserAdmin에서 사용하기 위함

from django import forms
from django.contrib.auth.forms import (
    ReadOnlyPasswordHashField,
)
from .models import User
from .utils import generate_unique_user_code


class UserCreationForm(forms.ModelForm):
    """
    A form for creating new users. Includes all the
    required fields, plus a repeated password.
    """

    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(
        label="Password confirmation", widget=forms.PasswordInput
    )

    class Meta:
        model = User
        fields = ("phone", "user_type")

    def clean_password2(self):
        # Check the two password entries match
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        # Save the provided password in hashed format
        user = super().save(commit=False)
        # Django admin을 통해 유저 생성시 user_code를 자동으로 추가시켜줌
        user.user_code = generate_unique_user_code(user.user_type)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class UserChangeForm(forms.ModelForm):
    """
    A form for updating users. Includes all the fields on
    the user, but replaces the password field with admin's
    password hash display field.
    """

    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = ("phone", "password", "is_active", "is_superuser")

    def clean_password(self):
        # Regardless of what the user provides, return the initial value.
        # This is done here, rather than on the field, because the
        # field does not have access to the initial value
        return self.initial["password"]

    def save(self, commit=True):
        # 유저 수정시 is_staff 체크를 하게 되면
        # 유저명을 user_code로 설정
        user = super().save(commit=False)
        if user.is_staff is True:
            user.user_code = user.username
            user.user_type = "A"
            user.status_id = 4
            user.save()
        return super().save(commit)
