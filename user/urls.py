from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter
from django.contrib.auth.views import LogoutView


from . import views


router = DefaultRouter()
router.register('admin', views.AdminViewSet, basename='Admin Reg')
router.register('agent', views.AgentViewSet)


urlpatterns = [
    re_path(r'^.*\.html', views.pages, name='pages'),
    path('index/', views.index, name = 'home'),
    path('login/', views.login_view, name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path('userlogin/', views.UserLoginApiView.as_view(), name = 'user_login'),
    path('adminsignup/', views.AdminCreateView.as_view(), name='admin_signup'),
    path('agentsignup/', views.AgentSignupView.as_view(), name='agent_signup'),
    path('activate/<uidb64>/<token>/', views.ActivateAccount.as_view(), name='activate'),
    path('adminupdate/', views.AdminUpdateView.as_view(), name='admin_update'),
    path('password_change/', views.ChangePasswordView.as_view(), name='admin_password_change'),
    path('', include(router.urls)),
]