from django.http import JsonResponse
from .models import *
from rest_framework.permissions import IsAuthenticated
from .serializers import *
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from knox.auth import AuthToken
from rest_framework.authtoken.serializers import AuthTokenSerializer
from django.shortcuts import render, redirect
from django.contrib import messages
from django_otp import devices_for_user
from django_otp.plugins.otp_email.models import EmailDevice
from .permissions import IsEmailVerified

EMPLOYEE = 'Employee'
CUSTOMER = 'Customer'
ADMIN = 'Admin'

@api_view(["POST"])
def Employee_register(request):
    user_type = request.data.get("user_type", None)
    serializer = RegisterUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    _, token = AuthToken.objects.create(user)

    current_user = User.objects.get(pk=user.id)
    if current_user.user_type == EMPLOYEE:
        current_user.is_staff=True
        current_user.save()

    return Response(
        {
            "user_infos": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "message": "Account Created Successfully.",
        }
    )

@api_view(["POST"])
def Employee_Customer(request):
    user_type = request.data.get("user_type", None)
    serializer = RegisterUserSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()

    _, token = AuthToken.objects.create(user)

    current_user = User.objects.get(pk=user.id)
    if current_user.user_type == CUSTOMER:
        current_user.is_staff=False
        current_user.save()

    return Response(
        {
            "user_infos": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "message": "Account Created Successfully.",
        }
    )


@api_view(["POST"])
def login(request):
    serializer = AuthTokenSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    user = serializer.validated_data["user"]

    _, token = AuthToken.objects.create(user)

    return Response(
        {
            "user_info": {
                "id": user.id,
                "username": user.username,
            },
            "token": token,
        }
    )

# @api_view(["POST"])
# @permission_classes([IsAuthenticated])
# def send_email_otp(request):
#     user = request.user
#     if user.is_anonymous:
#         return redirect('login')

#     if request.method == 'POST':
#         otp = OTP.objects.get(user=user)
#         if not otp.email_otp_enabled:
#             otp.enable_email_otp()

#         email_device = otp.email_device
#         if email_device:
#             email_device.generate_challenge()
#             email_device.send_token()
#             messages.success(request, 'OTP sent to your email address.')
#         else:
#             messages.error(request, 'Could not send OTP to your email address.')

#         return redirect('send_email_otp')

#     return render(request, 'send_email_otp.html')



@api_view(['GET'])
@permission_classes([IsAuthenticated])
def customer_view(request):
    # Your view code here
    return Response({'message': 'Hello, Client View!'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def employee_view(request):
    if request.user.is_staff != True:
            return Response({"message": "Get Authenticated First"})
    # Your view code here
    return Response({'message': 'Hello, Employee View!'})