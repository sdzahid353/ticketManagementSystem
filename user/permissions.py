from rest_framework import permissions


class HasAdminPermission(permissions.BasePermission):
    """Allow users to edit their own profile"""

    def has_permission(self, request, view):
        return request.user.is_superuser



class ProfilePermission(permissions.BasePermission):
    """Allow users to edit their own profile"""

    def has_object_permission(self, request, view, obj):
        """Check user is trying to edit their own profile"""
        if request.method in permissions.SAFE_METHODS:
            return True

        print('::: obj.id :::')
        print(obj.id)
        print('::: req user id :::')
        print(request.user.id)
        return obj.id == request.user.id