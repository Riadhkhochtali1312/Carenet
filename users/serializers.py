from django.contrib.auth import get_user_model
from djoser.serializers import UserCreateSerializer as DjoserUserCreateSerializer
from rest_framework import serializers
from djoser.serializers import TokenCreateSerializer


User = get_user_model()

class UserCreateSerializer(DjoserUserCreateSerializer):
    is_active = serializers.BooleanField(default=False)
    password_confirm = serializers.CharField(write_only=True)

    

    class Meta(DjoserUserCreateSerializer.Meta):
        fields = ('email', 'username', 'password', 'password_confirm', 'first_name', 'last_name')

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords do not match")
        return attrs
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        username = validated_data.pop('username')
        user = User.objects.create_user(username=username, **validated_data, password=password)
        return user
class CustomTokenCreateSerializer(TokenCreateSerializer):
    username_field = 'email'  # Use email as the username field

    def validate(self, attrs):
        attrs = super().validate(attrs)
        user = attrs['user']
        if not user.is_active:
            raise serializers.ValidationError('User account is disabled.')
        return attrs