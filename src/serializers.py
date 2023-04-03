from rest_framework import serializers,validators
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.models import User
from rest_framework import serializers
from .models import *


class RegisterUserSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "email",
            "password1",
            "password2",
            "user_type",
            "phone_number",
            "second_number",
            "national_id",
            "province",
            "district",
            "sector",
            "cell",
            "property_number",
            "gender",
            "age",

        )
        extra_kwargs = {
            "first_name": {"required": True},
            "last_name": {"required": True},
            "email": {
                "required": True,
                "allow_blank": False,
                "validators": [
                    validators.UniqueValidator(
                        User.objects.all(), "User with this email already exists"
                    )
                ],
            },
            "user_type": {"required": True},
            "phone_number":{"required": True},
            "second_number":{"required": True},
            "national_id": {"required": True},
            "province": {"required": True},
            "district": {"required": True},
            "sector": {"required": True},
            "cell": {"required": True},
            "property_number": {"required": True},
            "gender": {"required": True},
            "age": {"required": True},
        }

    def validate(self, attrs):
        if attrs["password1"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password Fields didn't match"}
            )

        return attrs

    def create(self, validated_data):
        first_name = validated_data.get("first_name")
        last_name = validated_data.get("last_name")
        email = validated_data.get("email")
        user_type = validated_data.get("user_type")

        user = User.objects.create(
            username=email, first_name=first_name, last_name=last_name, email=email, user_type=user_type
        )

        user.set_password(validated_data["password1"])
        user.save()

        return user


class AuthTokenSerializer(serializers.Serializer):
    """
    Serializer for auth token requests.
    """

    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, attrs):
        """
        Validate and authenticate the user credentials.
        """
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                email=email, password=password)
            if not user:
                msg = _('Unable to authenticate with provided credentials')
                raise serializers.ValidationError(msg, code='authentication')

        else:
            msg = _('Must include "email" and "password"')
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs
