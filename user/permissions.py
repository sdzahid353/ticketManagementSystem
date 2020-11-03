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
        # if request.method in permissions.SAFE_METHODS:
        #     return True

        print(obj.created_by)
        return obj.id == request.user.id

class CompanyPermission(permissions.BasePermission):
    """Allow users to edit their own profile"""

    def has_object_permission(self, request, view, obj):
        """Check user is trying to edit their own profile"""
        # if request.method in permissions.SAFE_METHODS:
        #     return True
        return ((obj.company_site == request.user.company_site) and request.user.is_superuser)  

