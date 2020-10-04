from rest_framework import serializers
from . import models


class AgentSerializer(serializers.ModelSerializer):
    """Serializes a user profile object"""

    class Meta:
        model = models.UserProfile
        fields = ('id', 'name', 'email', 'username', 'password','created_by')
        extra_kwargs = {
            'password' : {
                'write_only' : True,
                'style' : {'input_type' : 'password'}
            },
            'created_by' : {
                'read_only' : True
            }
        }
    
    def create(self, validated_data):
        """Create and return a new user"""

        user = models.UserProfile.objects.create_user(
            name=validated_data['name'],
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'], 
            created_by =  self.context["request"].user 
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


    class Meta:
        model = models.UserProfile
        fields = ('id', 'email', 'name', 'username', 'password', 'company_site')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'}
            }
        }

    def create(self, validated_data):
        """Create and return a new admin"""
        print("::: validated_data :::")
        print(validated_data)
        user = models.UserProfile.objects.create_superuser(
            name=validated_data['name'],
            email=validated_data['email'],
            username=validated_data['username'],
            password=validated_data['password'],
            company_site=validated_data['company_site']
        )

        print(validated_data.get('created_by'))
        return user


    def update(self, instance, validated_data):
        """Handle updating admin account"""
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)

        return super().update(instance, validated_data)
        