from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.db.models import Q

from .models import UserProfile



class MyModelAdmin(admin.ModelAdmin):
    readonly_fields = ('created_by', )
    list_display = ('username', 'email', 'name', 'is_superuser', 'is_staff', 'created_by')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('username', 'name', 'email')
    # ordering = ('username',)


    # def has_delete_permission(self, request, obj=None):
    #     print("object")
    #     print(obj)
    #     print("requested email")
    #     print(request.user.email)
    #     return request.user.email == obj

    
    def get_queryset(self, request):
        qs = super(MyModelAdmin, self).get_queryset(request)
        # if request.user.is_superuser:
        #     return qs
        return qs.filter(Q(created_by=request.user) | Q(username=request.user.username) | Q(company_site=request.user.company_site))




admin.site.register(UserProfile, MyModelAdmin)

# admin.site.unregister(UserProfile)

# @admin.register(UserProfile)
# class CustomUserAdmin(UserAdmin):
#     pass
