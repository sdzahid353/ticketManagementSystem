from django.shortcuts import render
from django.db.models import Q
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny

from . import models, serializers


class TicketViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.TicketSerializer
    queryset = models.Ticket.objects.all()

    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)


    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        print(request.user.is_superuser)
        if request.user.is_superuser == False:
            print("Working")
            request.data._mutable = True
            print(request.data.get('assigned_to'))
            print(request.user)
            request.data.update({"assigned_to": request.user.id})
            print(request.data.get('assigned_to'))
            request.data._mutable = False
        serializer.is_valid(raise_exception=True)
        serializer.save()
        headers = self.get_success_headers(serializer.data)
        # mail_subject = 'Welcome to My Company'
        # message = render_to_string('admin_email.html', {
        #     'user': request.data.get('name'),
        #     'company_site' : request.data.get('company_site'),
        # })
        # to_email = request.data.get('email')
        # email = EmailMessage(
        #             mail_subject, message, to=[to_email]
        # )
        # email.send()
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def list(self, request, *args, **kwargs):
        print("List")
        print(request.user)
        if not request.user.is_superuser:
            queryset = models.Ticket.objects.filter(Q(created_by=request.user.id) | Q(assigned_to=request.user.id))
        else:
            queryset = models.Ticket.objects.filter(Q(created_by__company_site=request.user.company_site) | Q(created_by__created_by=request.user.id))

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        print("****** retrieve ******")
        print("instance")
        print(instance)
        serializer = self.get_serializer(instance)
        print("serializer")
        print(serializer)
        print("serializer.data")
        print(serializer.data)
        print(request.user.created_by)
        if request.user.id == serializer.data.get('created_by'):
            print(serializer.created_by)
            return Response(serializer.data)
        return Response({"Message" : "You don't have permission"})

class CustomerViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.CustomerSerializer
    queryset = models.Customer.objects.all()
