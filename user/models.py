from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager
from django.conf import settings


class UserProfileManager(BaseUserManager):
    """Manager for user profiles"""

    def create_user(self, email, name, username, created_by, password=None, company_site=None):
        """Create a new user profile"""
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        user = self.model(email=email, name=name, username=username)

        user.set_password(password)
        if created_by:
            user.created_by=created_by
        if company_site:
            user.company_site = company_site

        user.save(using=self._db)

        return user

    def create_superuser(self, email, name, username, password, company_site):
        """Create and save a new superuser with given details"""
        user = self.create_user(email, name, username, None, password, company_site)

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
    REQUIRED_FIELDS = ['name', 'email', 'company_site']

    def first_name(self):
        """Retrieve full name for user"""
        return self.name

    def last_name(self):
        """Retrieve short name of user"""
        return self.name

    def __str__(self):
        """Return string representation of user"""
        return self.email


