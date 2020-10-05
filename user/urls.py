from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views


router = DefaultRouter()
router.register('admin', views.AdminViewSet, basename='Admin Reg')
router.register('agent', views.AgentViewSet)


urlpatterns = [
    path('login/', views.UserLoginApiView.as_view()),
    path('adminsignup/', views.AdminCreateView.as_view()),
    path('signup/', views.signup, name='signup'),
    path('adminupdate/<int:pk>', views.AdminUpdateView.as_view()),
    path('', include(router.urls)),
]