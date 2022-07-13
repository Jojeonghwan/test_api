from django.shortcuts import render

from rest_framework import permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response


@api_view(["GET"])
@permission_classes((permissions.AllowAny,))
def sample_app_view(request):
    """
    get:
        - sample_app_view
    """

    result = {"result": "HelloWorld!!"}

    return Response(result)
