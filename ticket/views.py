from django.shortcuts import render,redirect, get_object_or_404
from django.db.models import Q
from rest_framework import viewsets,generics, status
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from pprint import pprint
from django.core.paginator import Paginator
from rest_framework.permissions import IsAuthenticated
from . import models, serializers
from django.views.generic.edit import DeleteView
from django.urls import reverse_lazy
from django.http import HttpResponseRedirect
from django.urls import reverse
from  user.models import UserProfile

class TicketlistView(generics.ListAPIView):
    serializer_class = serializers.TicketSerializer
    queryset = models.Ticket.objects.all()

    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (IsAuthenticated,)


    # def create(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     if request.user.is_superuser == False:
    #         request.data._mutable = True
    #         request.data.update({"assigned_to": request.user.id})
    #         request.data._mutable = False
    #     serializer.is_valid(raise_exception=True)
    #     serializer.save()
    #     headers = self.get_success_headers(serializer.data)
    #     return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def list(self, request, *args, **kwargs):
        print("List")
        print(request.user)
        if not request.user.is_authenticated:
            return redirect('/login/')
        if not request.user.is_superuser:
            queryset = models.Ticket.objects.filter(Q(created_by=request.user.id) | Q(assigned_to=request.user.id))
        else:
            queryset = models.Ticket.objects.filter(Q(created_by__company_site=request.user.company_site) | Q(created_by__created_by=request.user.id))

        paginator = Paginator(queryset, 5)

        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)

        tickets = paginator.page(page_number)
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return render(request,  'tickets.html', {"tickets" : tickets})

    # def retrieve(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(instance)
    #     if (request.user.is_superuser and request.user.company_site == instance.created_by.company_site)  or request.user.id == serializer.data.get('created_by') or request.user.id == instance.assigned_to.id:
    #         return Response(serializer.data)
    #     return Response({"Message" : "You don't have permission"})



class  TicketcreateView(generics.ListCreateAPIView):
    serializer_class = serializers.TicketSerializer
    queryset = models.Ticket.objects.all()
    template_name = 'add_ticket.html'


    msg     = None
    
    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (IsAuthenticated,)


    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('/login/')
        serializer = self.get_serializer()
        users = UserProfile.objects.filter(Q(company_site=request.user.company_site) & Q(is_superuser=False))       
        return render(request, self.template_name, {'form': serializer,"msg" : None,"admin":request.user.is_superuser,'users':users})
        


    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if request.user.is_superuser == False:
            request.data._mutable = True
            request.data.update({"assigned_to": request.user.id})
            request.data._mutable = False
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return render(request, self.template_name, {'form': serializer,"msg":'Ticket created' })
        return render(request, self.template_name, {"data": request.data,'form': serializer,'msg':None})
       
        
        
        

class TicketViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.TicketSerializer
    queryset = models.Ticket.objects.all()

    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (IsAuthenticated,)


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
        print("** retrieve **")
        print("instance")
        serializer = self.get_serializer(instance)
        print("serializer")
        print(serializer)
        print("serializer.data")
        print(serializer.data)
        print(request.user.created_by)
        if (request.user.is_superuser and request.user.company_site == instance.created_by.company_site)  or request.user.id == serializer.data.get('created_by') or request.user.id == instance.assigned_to.id:
            return Response(serializer.data)
        return Response({"Message" : "You don't have permission"})

class CustomerViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.CustomerSerializer
    queryset = models.Customer.objects.all()



class TicketDeleteView(DeleteView):
    queryset = models.Ticket.objects.all()
    template_name = 'ticket_delete.html'
    success_url = reverse_lazy('tickets_list')

    def get(self, request, *args, **kwargs):
        self.object = self.get_object()
        if (request.user.is_superuser == True and request.user==self.object.created_by):
            return render(request, 'ticket_delete.html',{'object' : self.object, 'permission':True})
        return render(request, 'ticket_delete.html',{'permission':False})
      
    

    def delete(self, request, *args, **kwargs):
        if not models.Ticket.objects.filter(pk=self.kwargs['pk']):
            return render(request, self.template_name, {'permission':False})
        self.object = self.get_object()
        success_url = self.get_success_url()
        self.object.delete()
        return redirect('tickets_list')






class TicketDetailView(generics.RetrieveAPIView):
    serializer_class = serializers.TicketSerializer
    queryset = models.Ticket.objects.all()

    def retrieve(self, request, *args, **kwargs):
        # if not models.UserProfile.objects.filter(pk=self.kwargs['pk']):
        #     return render(request, 'agent_detail.html', {'permission':False})
        if not request.user.is_authenticated:
            return redirect('/login/')
        if not models.Ticket.objects.filter(pk=self.kwargs['pk']):
            return render(request, 'agent_detail.html', {'permission':False})
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        created_by = instance.created_by.email
        assigned_to = instance.assigned_to.email
        if (request.user.is_superuser and request.user.company_site == instance.created_by.company_site)  or request.user.id == serializer.data.get('created_by') or request.user.id == instance.assigned_to.id:
            return render(request, 'ticket_detail.html',{"ticket" : serializer.data, "created_by" : created_by, "assigned_to" : assigned_to, "permission" : True})
        return Response({"Message" : "You don't have permission"})
        



class TicketUpdateView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.TicketUpdateSerializer
    queryset = models.Ticket.objects.all()
    template_name = 'ticket_update.html'

    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (permissions.ProfilePermission, permissions.HasAdminPermission)

    msg     = None
    success = False

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        agents = UserProfile.objects.filter(Q(company_site=request.user.company_site) & Q(is_superuser=False))        # if request.user.is_superuser and request.user.company_site == instance.created_by.company_site:
        #     return render(request, self.template_name, {'form': serializer, "msg" : None,  "permission" : True})
        return render(request, self.template_name, {'form': serializer.data, "msg" : None,"agnets":agents})


    def post(self, request, *args, **kwargs):
        instance = get_object_or_404(models.Ticket, id=self.kwargs['pk'])
        serializer = self.get_serializer(instance=instance,data=request.data)
        if request.user.is_superuser and request.user.company_site == instance.created_by.company_site:
            if serializer.is_valid(raise_exception=True):
                serializer.save()
            return render(request, self.template_name, {'form': serializer.data,"msg":'Ticket updated' })
        return render(request, self.template_name, {"data": request.data,'form': serializer,'msg':None})
       


       