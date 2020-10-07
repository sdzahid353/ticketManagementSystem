from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views


router = DefaultRouter()
router.register('admin', views.AdminViewSet, basename='Admin Reg')
router.register('agent', views.AgentViewSet)


urlpatterns = [
    path('index/', views.index, name = 'index'),
    path('login/', views.UserLoginApiView.as_view(), name = 'login'),
    path('adminsignup/', views.AdminCreateView.as_view()),
    path('agentsignup/', views.AgentSignupView.as_view(), name='agent_signup'),
    path('activate/<uidb64>/<token>/', views.ActivateAccount.as_view(), name='activate'),
    path('adminupdate/<int:pk>', views.AdminUpdateView.as_view()),
    path('', include(router.urls)),
]