from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
import random

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.is_active = False  # Deactivate until email is verified
        user.save()

        # Generate OTP and send email
        otp = random.randint(1000, 9999)
        user.otp = otp
        user.save()

        send_mail(
            'Email Verification Code',
            f'Your OTP code is {otp}',
            'noreply@example.com',
            [user.email],
            fail_silently=False,
        )
        return user


class VerifyEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.IntegerField()

    def validate(self, data):
        email = data.get('email')
        otp = data.get('otp')

        try:
            user = User.objects.get(email=email, otp=otp)
            user.is_active = True
            user.otp = None
            user.save()
        except User.DoesNotExist:
            raise serializers.ValidationError('Invalid OTP or Email')

        return data


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        user = User.objects.filter(email=email).first()
        if user and user.check_password(password):
            if not user.is_active:
                raise serializers.ValidationError('User is not verified!')
            return {
                'email': user.email,
                'tokens': str(RefreshToken.for_user(user).access_token),
            }
        raise serializers.ValidationError('Invalid credentials')
