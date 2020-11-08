from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register('ticket', views.TicketViewSet, basename='ticket')
router.register('customer', views.CustomerViewSet, basename='customer')

urlpatterns = [
    path('', include(router.urls)),
    path('tickets/', views.TicketlistView.as_view(), name='tickets_list'),
    path('create_ticket/', views.TicketcreateView.as_view(), name='create_ticket'),
]
