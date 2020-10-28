from rest_framework import serializers
from django.db import models
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from .models import UserProfile
from django.contrib.auth.hashers import make_password

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
        """Handle updating agent account"""
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)

        if validated_data['name'] == '':
            validated_data['name'] = instance.name
        if validated_data['username'] == '':
            validated_data['username'] = instance.username
        if validated_data['email'] == '':
            validated_data['email'] = instance.email

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
    
    
    def validate(self, data):
        return data

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

        if validated_data['name'] == '':
            validated_data['name'] = instance.name
        if validated_data['username'] == '':
            validated_data['username'] = instance.username
        if validated_data['email'] == '':
            validated_data['email'] = instance.email
        if validated_data['company_site'] == '':
            validated_data['company_site'] = instance.company_site

        return super().update(instance, validated_data)


class ChangePasswordSerializer(serializers.ModelSerializer):
    model = UserProfile

    """
    Serializer for password change endpoint.
    """
    # old_password = serializers.CharField(max_length=128, write_only=True, required=True)
    new_password = serializers.CharField(max_length=128, write_only=True, required=True)
    confirm_new_password = serializers.CharField(max_length=128, write_only=True, required=True)

    class Meta:
        model = UserProfile
        fields = ("password", "new_password", "confirm_new_password")


    def update(self, instance, validated_data):
        """Handle updating admin account"""
        # if 'password' in validated_data:
        password = validated_data['new_password']
        instance.set_password(password)
        instance.save()
        return instance

        # return super().update(instance, validated_data)




class AgentUpdateSerializer(serializers.ModelSerializer):
    """Serializes a user profile object"""

    class Meta:
        model = UserProfile
        fields = ('id', 'name', 'email', 'username')
        

  

    def update(self, instance, validated_data):
        """Handle updating agent account"""
      
        if validated_data['name'] == '':
            validated_data['name'] = instance.name
        if validated_data['username'] == '':
            validated_data['username'] = instance.username
        if validated_data['email'] == '':
            validated_data['email'] = instance.email

        return super().update(instance, validated_data)





class AgentChangePasswordSerializer(serializers.ModelSerializer):
    

    """
    Serializer for password change endpoint.
    """
    new_password = serializers.CharField(max_length=128, write_only=True, required=True)



    class Meta:
        model = UserProfile
        fields = ("id", "email", "new_password",)
        extra_kwargs = {
            'email': {
                'read_only': True,
            }
        }


    def update(self, instance, validated_data):
        """Handle updating admin account"""
        password = validated_data['new_password']
        instance.set_password(password)
        instance.save()
        return instance

     
