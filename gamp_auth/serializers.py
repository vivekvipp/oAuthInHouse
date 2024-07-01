from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'mobile_no', 'is_active', 'is_staff', 'is_superuser']


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
