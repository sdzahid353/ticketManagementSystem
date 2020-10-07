# Ticket Management System

## Installing virtualenv

### On macOS and Linux:

    python3 -m pip install --user virtualenv (pip install virtualenv)

### On Windows:

    py -m pip install --user virtualenv (pip install virtualenv)


## Creating a virtual environment

### On macOS and Linux:

    python3 -m venv env (virtualenv venv)

### On Windows:

    py -m venv env (virtualenv venv)


## Activating a virtual environment

### On macOS and Linux:

    source venv/bin/activate

### On Windows:

    .\venv\Scripts\activate.bat


## Leaving the virtual environment

    deactivate


## Using requirements files

    pip install -r requirements.txt


## Freezing dependencies

    pip freeze > requirements.txt

    pip freeze


## Installing Requirements

    pip install django
    pip install djangorestframework



## Explanation

### Installing django and djangorestframework

After activating Virtualenv install **django** and **djangorestframework** by using following following commands

    pip install django
    pip install djangorestframework


### Create project

And create project(TMS) by using following command

    django-admin startproject TMS

### Modify settings.py

Now add **'rest_framework'** and **'rest_framework.authtoken'** in INSTALLED_APPS of settings.py file

    INSTALLED_APPS = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'rest_framework',
        'rest_framework.authtoken',
    ]

and change TIME_ZONE from **'UTC'** to **'Asia/Kolkata'** in settings.py

    TIME_ZONE = 'Asia/Kolkata'

Before migrating check once for cd(Current Directory)

If not in the project then we should dive into the project directory

now migrate to migrate all migrations of INSTALLED_APPS by using following command

    python manage.py migrate

### create user app

Now create a new app called **user** for custom user management

    python manage.py startapp user

Add the following script in **models.py** of **user** app

### user/models.py

    from django.db import models
    from django.contrib.auth.models import AbstractBaseUser
    from django.contrib.auth.models import PermissionsMixin
    from django.contrib.auth.models import BaseUserManager
    from django.conf import settings


    class UserProfileManager(BaseUserManager):
        """Manager for user profiles"""

        def create_user(self, email, name, username, created_by, password=None):
            """Create a new user profile"""
            if not email:
                raise ValueError('Users must have an email address')

            email = self.normalize_email(email)
            user = self.model(email=email, name=name, username=username)

            user.set_password(password)
            if created_by:
                user.created_by=created_by

            user.save(using=self._db)

            return user

        def create_superuser(self, email, name, username, password, company_site):
            """Create and save a new superuser with given details"""
            user = self.create_user(email, name, username, None, password)

            user.company_site = company_site
            user.is_superuser = True
            user.save(using=self._db)

            return user


    class UserProfile(AbstractBaseUser, PermissionsMixin):
        """Database model for users in the system"""
        name = models.CharField(max_length=255)
        email = models.EmailField(max_length=255, unique=True)
        username = models.CharField(max_length=255, unique=True)
        company_site = models.URLField(blank=False)
        is_active = models.BooleanField(default=True)
        is_staff = models.BooleanField(default=True)
        created_by = models.ForeignKey(
            settings.AUTH_USER_MODEL,
            blank=True,
            null=True,
            on_delete=models.CASCADE
        )

        objects = UserProfileManager()

        USERNAME_FIELD = 'username' or 'email'
        REQUIRED_FIELDS = []

        def get_full_name(self):
            """Retrieve full name for user"""
            return self.name

        def get_short_name(self):
            """Retrieve short name of user"""
            return self.name

        def __str__(self):
            """Return string representation of user"""
            return self.email



Here in user/models.py create a model called **UserProfile** for custom user and in that **'created_by'** field should refer to **settings.AUTH_USER_MODEL** using by foreign key 

For **settings.AUTH_USER_MODEL** we add **AUTH_USER_MODEL = 'user.UserProfile'** in settings.py file

    AUTH_USER_MODEL = 'user.UserProfile'



### user/serializers.py

Now create **AgentSerializer** and **AdminSerializer** in serialiers.py of user app

    from rest_framework import serializers
    from . import models


    class AgentSerializer(serializers.ModelSerializer):
        """Serializes a user profile object"""

        class Meta:
            model = models.UserProfile
            fields = ('id', 'name', 'email', 'username', 'password',)
            extra_kwargs = {
                'password' : {
                    'write_only' : True,
                    'style' : {'input_type' : 'password'}
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
            user = models.UserProfile.objects.create_superuser(
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


Before creating views we should create permissions

for that create a file called **permission.py** and create permission in that

### user/permissions.py

    from rest_framework import permissions


    class HasAdminPermission(permissions.BasePermission):
        """Allow users to edit their own profile"""

        def has_permission(self, request, view):
            """Check user is superuser or not"""

            return request.user.is_superuser



    class ProfilePermission(permissions.BasePermission):
        """Allow users to edit their own profile"""

        def has_object_permission(self, request, view, obj):
            """Check user is trying to edit their own profile"""
        
            return obj.id == request.user.id


Here for **HasAdminPermission** class we are checking the requested user is a superuer or not

and for **ProfilePermission** class we are checking that requested user is updating his own profile or not by using **object id**, if not then the permission is denied.

**And now we create views for admin signup, agent signup and logins.**

### user/viwes.py

    from rest_framework.views import APIView
    from rest_framework import generics
    from rest_framework.response import Response
    from rest_framework import viewsets,status
    from rest_framework.authentication import TokenAuthentication
    from rest_framework.authtoken.views import ObtainAuthToken
    from rest_framework.permissions import IsAuthenticated, AllowAny
    from rest_framework.settings import api_settings
    from rest_framework import filters
    from django.http import HttpResponse
    from django.shortcuts import render, redirect
    from django.contrib.auth import login, authenticate
    from django.contrib.sites.shortcuts import get_current_site
    from django.utils.encoding import force_bytes, force_text
    from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
    from django.template.loader import render_to_string
    from django.core.mail import EmailMessage


    from . import serializers, models, permissions
    

    class AdminViewSet(viewsets.ModelViewSet):
        """Handle creating, creating and updating profiles"""
        serializer_class = serializers.AdminSerializer
        queryset = models.UserProfile.objects.all()

        authentication_classes = (TokenAuthentication,)
        permission_classes = (permissions.ProfilePermission,)



    class AgentViewSet(viewsets.ModelViewSet):
        """Handle creating, creating and updating profiles"""
        serializer_class = serializers.AgentSerializer
        queryset = models.UserProfile.objects.all()

        authentication_classes = [TokenAuthentication]
        permission_classes = (IsAuthenticated, permissions.HasAdminPermission) 

        def create(self, request, *args, **kwargs):
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(
                {
                    'serializer data' : serializer.data,
                    'agent_data' : {
                        'username' : request.data.get('username'),
                        'password' : request.data.get('password')
                    }
                },
                status=status.HTTP_201_CREATED, headers=headers
            )
        

        def perform_create(self, serializer):
            serializer.save()


        def list(self, request, *args, **kwargs):
            queryset = models.UserProfile.objects.filter(created_by=request.user.id)

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)


        filter_backends = (filters.SearchFilter,)
        search_fields = ('name', 'email',)



    class AdminCreateView(generics.CreateAPIView):
        serializer_class = serializers.AdminSerializer
        queryset = models.UserProfile.objects.all()

        # authentication_classes = (TokenAuthentication,)
        # permission_classes = (permissions.ProfilePermission,)


    class AdminUpdateView(generics.RetrieveUpdateDestroyAPIView):
        serializer_class = serializers.AdminSerializer
        queryset =  models.UserProfile.objects.all()

        authentication_classes = (TokenAuthentication,)
        permission_classes = (permissions.ProfilePermission, permissions.HasAdminPermission)


    class UserLoginApiView(ObtainAuthToken):
    """Handle creating user authentication tokens"""
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES


In views.py **AdminViewSet** and **AgentViewSet** inherits from **ModelViewSet** which will be used to do all **CRUD** operations

**UserLoginApiView** is used as login api which returns the token of logged user

**AdminCreateView** is used to do only **POST** method

**AdminUpdateView** is used to do **GET, PUT, PATCH & DELETE** methods



Now we will create endpoints in **urls.py** file.Before that we should create **urls.py** file

and add endpoints in **urls.py**


### user/urls.py

    from django.urls import path, include
    from rest_framework.routers import DefaultRouter

    from . import views


    router = DefaultRouter()
    router.register('admin', views.AdminViewSet, basename='Admin Reg')
    router.register('agent', views.AgentViewSet)


    urlpatterns = [
        path('login/', views.UserLoginApiView.as_view()),
        path('adminsignup/', views.AdminCreateView.as_view()),
        path('adminupdate/<int:pk>', views.AdminUpdateView.as_view()),
        path('', include(router.urls)),
    ]


**update the main project(TMS) urls.py file**

### TMS/urls.py

    from django.contrib import admin
    from django.urls import path, include

    urlpatterns = [
        path('admin/', admin.site.urls),
        path('user/', include('user.urls')),
    ]


Now the following are the end points for user(Both Admin & Agent) signup and login

### Admin Signup Endpoint(s)

    http://127.0.0.1:8000/user/admin/

                    OR

    http://127.0.0.1:8000/user/adminsignup/


### Admin Login Endpoint

    http://127.0.0.1:8000/user/login/

### Agent Signup Endpoint

Remember here agent is not able to Signup as that agent account is created only by Admin for that we have added a permissions in **AgentViewSet** are **IsAuthenticated & HasAdminPermission**

    http://127.0.0.1:8000/user/agent/


### Admin Update Endpoint(s)

Check permissions for admin update/delete in **AdminViewSet** & **AdminUpdateView**

    http://127.0.0.1:8000/user/admin/<int:pk>

                    OR

    http://127.0.0.1:8000/user/adminupdate/<int:pk>



Now the **REQUIRED_FIELDS** list is append with **'name', 'email', 'company_site'** in **user/models.py** for our requirement as we want to create superuser using terminal

    REQUIRED_FIELDS = ['name', 'email', 'company_site']


In **user/views.py** we should override some fuctions as per our convinient

Lets talk about agent

We want to apply somy restrictions to agent viewset as

* Agent account is created only by logged in Admin(superuser).
* The list of agents visible to that user who created those agents.
* The details agent is visible to that user who has created that agent.
* Update and delete operations are accessable only to that created admin.


For retrieving(getting), updating and deletion operation we should override the **retrieve**, **update** and **delete** fuctions in **AgentViewSet**

update the **AgentViewSet** in **user/views.py** with the following code

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        print(instance)
        serializer = self.get_serializer(instance)
        if request.user.id == serializer.data.get('created_by'):
            return Response(serializer.data)
        return Response({"Message" : "You don't have permission"})


    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.created_by == request.user:
            partial = kwargs.pop('partial', False)
            print(instance.created_by)
            print(instance)
            print(request.user)
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)

            if getattr(instance, '_prefetched_objects_cache', None):
                # If 'prefetch_related' has been applied to a queryset, we need to
                # forcibly invalidate the prefetch cache on the instance.
                instance._prefetched_objects_cache = {}

            return Response(serializer.data)
        return Response({"Message" : "You don't have permission to update"})
        

    def perform_update(self, serializer):
        serializer.save()

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)


    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.created_by == request.user:
            self.perform_destroy(instance)
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"Message" : "You don't have permission to delete"})

    def perform_destroy(self, instance):
        instance.delete()


Now another problem is rising here, when we visit the **AdminViewSet** end point **http://127.0.0.1:8000/user/admin/** , it displays the complete users(Admins & Agents) list. So we should filter here to display only the admins and the admins belongs to same company to the logged in superuser(Admin) 

For getting list of admins belongs to same company/organisation we should override the **list** function in **AdmintViewSet**

Update the **AdminViewSet** in **user/views.py** with the following code

    def list(self, request, *args, **kwargs):
        
        if request.user.is_superuser:
            queryset = models.UserProfile.objects.filter(company_site=request.user.company_site)

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        return Response({"Message" : "You don't have permission to view"})


