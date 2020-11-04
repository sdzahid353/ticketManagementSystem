from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter
from django.contrib.auth.views import LogoutView
from django.contrib.auth import views as auth_views


from . import views


router = DefaultRouter()
router.register('admin', views.AdminViewSet, basename='Admin Reg')
router.register('agent', views.AgentViewSet)

# app_name = 'users'

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
    path('forgot_password/', views.password_reset_request, name="password_reset"),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name="password/password_reset_confirm.html"), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password/password_reset_complete.html'), name='password_reset_complete'),
    path('agents/', views.AgentsView.as_view(), name='agents'),
    path('add_agents/', views.AgentCreateView.as_view(), name='add_agents'),
    path('agent_detail/<int:pk>', views.AgentDetailView.as_view(), name='agent_detail'),
    path('agent_update/<int:pk>', views.AgentUpdateView.as_view(), name='agent_update'),
    path('agent_delete/<int:pk>', views.AgentDeleteView.as_view(), name='agent_delete'),
    path('search/', views.SearchPostView.as_view(), name='search'),
    path('agent_password_change/<int:pk>',views.AgentChangePasswordView.as_view(),name="agent_password_change")
]