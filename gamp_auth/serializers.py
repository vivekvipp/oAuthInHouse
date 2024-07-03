from rest_framework import serializers
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from .models import User
import random
import string
import re


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'mobile_no', 'is_active', 'is_blocked', 'old_id']


def validate_mobile_no(value):
    if not re.match(r'^\+91\d{10}$', value):
        raise ValidationError("Mobile number must be in the format +91 followed by 10 digits.")
    return value


class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=False, validators=[EmailValidator()])
    mobile_no = serializers.CharField(required=False, validators=[validate_mobile_no])

    class Meta:
        model = User
        fields = ['mobile_no', 'email']

    def validate(self, data):
        if not data.get('email') and not data.get('mobile_no'):
            raise ValidationError("At least one of email or mobile_no must be provided.")

        if data.get('email') and User.objects.filter(email=data.get('email')).exists():
            raise ValidationError("A user with this email already exists.")

        if data.get('mobile_no') and User.objects.filter(mobile_no=data.get('mobile_no')).exists():
            raise ValidationError("A user with this mobile number already exists.")

        return data

    def create(self, validated_data):
        password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))

        email = validated_data.get('email')
        if email:
            email = email.lower()

        user = User.objects.create_user(
            mobile_no=validated_data.get('mobile_no'),
            email=email,
            password=password
        )
        user.set_password(password)
        user.save()

        return user


class OTPSendSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    mobile_no = serializers.CharField(required=False)

    def validate(self, data):
        if not data.get('email') and not data.get('mobile_no'):
            raise serializers.ValidationError('Either email or mobile number must be provided')
        return data


class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    mobile_no = serializers.CharField(required=False)
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        if not data.get('email') and not data.get('mobile_no'):
            raise serializers.ValidationError('Either email or mobile number must be provided')
        return data
