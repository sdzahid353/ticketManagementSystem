from rest_framework import serializers
from django.db import models
from .models import UserProfile


class AgentSerializer(serializers.ModelSerializer):
    """Serializes a user profile object"""

    class Meta:
        model = UserProfile
        fields = ('id', 'name', 'email', 'username', 'password','created_by', 'company_site')
        extra_kwargs = {
            'password' : {
                'write_only' : True,
                'style' : {'input_type' : 'password'}
            },
            'created_by' : {
                'read_only' : True
            },
            'company_site' : {
                'read_only' : True
            }
        }
    
    def create(self, validated_data):
        """Create and return a new user"""

        user = UserProfile.objects.create_user(
            name=validated_data['name'],
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'], 
            created_by =  self.context["request"].user,
            company_site = self.context['request'].user.company_site
        )

        return user

    def update(self, instance, validated_data):
        """Handle updating user account"""
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)

        return super().update(instance, validated_data)



class AdminSerializer(serializers.ModelSerializer):
    """Serializes a Admin profile object"""

    agentss = AgentSerializer(many=True, read_only=True)

    class Meta:
        model = UserProfile
        fields = ('id', 'email', 'name', 'username', 'password', 'company_site', 'agentss')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'}
            }
        }

    def create(self, validated_data):
        """Create and return a new admin"""
        # agents_data = validated_data.pop('agents')
        user = UserProfile.objects.create_superuser(
            name=validated_data['name'],
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            company_site=validated_data['company_site']
        )

        return user


    def update(self, instance, validated_data):
        """Handle updating admin account"""
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)

        return super().update(instance, validated_data)
        