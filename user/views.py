from rest_framework.views import APIView
from rest_framework import generics
from django.views.generic import View, UpdateView
from rest_framework.response import Response
from rest_framework import viewsets,status
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.settings import api_settings
from rest_framework import filters
from django.http import HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.contrib import messages
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.db.models import Q
from django.template import loader
from django.http import HttpResponse
from django import template


from . import serializers, models, permissions, tokens
from . import forms



@login_required(login_url="/login/")
def index(request): 
    return render(request, 'index.html')

def login_view(request):
    form = forms.LoginForm(request.POST or None)

    msg = None

    if request.method == "POST":

        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect("/index")
            else:    
                msg = 'Invalid credentials'    
        else:
            msg = 'Error validating the form'    

    return render(request, "accounts/login.html", {"form": form, "msg" : msg})

@login_required(login_url="/login/")
def pages(request):
    context = {}
    # All resource paths end in .html.
    # Pick out the html file name from the url. And load that template.
    try:
        
        load_template = request.path.split('/')[-1]
        html_template = loader.get_template( load_template )
        return HttpResponse(html_template.render(context, request))
        
    except template.TemplateDoesNotExist:

        html_template = loader.get_template( 'error-404.html' )
        return HttpResponse(html_template.render(context, request))

    except:
    
        html_template = loader.get_template( 'error-500.html' )
        return HttpResponse(html_template.render(context, request))

class AgentSignupView(generics.CreateAPIView):
    form_class = forms.SignupForm
    serializer_class = serializers.AgentSerializer
    template_name = 'signup_agent.html'

    authentication_classes = [TokenAuthentication]

    def get(self, request, *args, **kwargs):
        form = self.form_class()
        serializer = self.get_serializer()
        if request.user.is_superuser:
            return render(request, self.template_name, {'form': serializer})
        raise PermissionDenied("You don't have permission.")

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)
        serializer = self.get_serializer(data=request.data)

        if request.data.get("password") != request.data.get("confirm_password"):
            return render(request, self.template_name, { "data": request.data, 'form': serializer, "error": "Password Mismatch"})

        if serializer.is_valid():

            user = serializer.save()
            user.created_by = request.user
            user.company_site = request.user.company_site
            user.is_active = False # Deactivate account till it is confirmed
            user.save()

            current_site = get_current_site(request)
            mail_subject = 'Activate Your Account'
            message = render_to_string('acc_email.html', {
                'user': user,
                'password' : request.data.get("password"),
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': tokens.account_activation_token.make_token(user),
            })
            # user.email_user(subject, message)
            print(request.POST.get('email'))
            to_email = request.data.get('email')
            email = EmailMessage(
                        mail_subject, message, to=[to_email]
            )
            email.send()

            messages.success(request, ('Please Confirm your email to complete registration.'))

            return redirect('login')

        return render(request, self.template_name, {"data": request.data,'form': serializer})


class ActivateAccount(View):

    def get(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = models.UserProfile.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and tokens.account_activation_token.check_token(user, token):
            user.is_active = True
            # user.profile.email_confirmed = True
            user.save()
            # login(request, user)
            messages.success(request, ('Your account have been confirmed.'))
            return redirect('index')
        else:
            messages.warning(request, ('The confirmation link was invalid, possibly because it has already been used.'))
            return redirect('index')



class AdminViewSet(viewsets.ModelViewSet):
    """Handle creating, creating and updating profiles"""
    serializer_class = serializers.AdminSerializer
    queryset = models.UserProfile.objects.all()

    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.ProfilePermission,)

    def list(self, request, *args, **kwargs):
        
        if request.user.is_superuser:
            queryset = models.UserProfile.objects.filter(Q(company_site=request.user.company_site) & Q(is_superuser=True))

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        return Response({"Message" : "You don't have permission to view"})

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        headers = self.get_success_headers(serializer.data)
        mail_subject = 'Welcome to My Company'
        message = render_to_string('admin_email.html', {
            'user': request.data.get('name'),
            'company_site' : request.data.get('company_site'),
        })
        to_email = request.data.get('email')
        email = EmailMessage(
                    mail_subject, message, to=[to_email]
        )
        email.send()
            
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('name', 'email',)


class AgentViewSet(viewsets.ModelViewSet):
    """Handle creating, creating and updating profiles"""
    serializer_class = serializers.AgentSerializer
    queryset = models.UserProfile.objects.all()

    authentication_classes = [TokenAuthentication]
    # permission_classes = (IsAuthenticated, permissions.HasAdminPermission, )
    permission_classes_by_action = {'create': [permissions.HasAdminPermission],
                                    'list': [permissions.HasAdminPermission],
                                    'retrive': [IsAuthenticated],
                                    'update': [permissions.CompanyPermission],
                                    'partial_update': [permissions.CompanyPermission],
                                    'destroy': [permissions.CompanyPermission],}

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            {
                'serializer data' : serializer.data,
                'agent_data' : {
                    'username' : request.data.get('username'),
                    'password' : request.data.get('password')
                }
            },
            status=status.HTTP_201_CREATED, headers=headers
        )
    

    def perform_create(self, serializer):
        serializer.save()


    def list(self, request, *args, **kwargs):
        queryset = models.UserProfile.objects.filter(Q(company_site=request.user.company_site) & Q(is_superuser=False))

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        if (request.user.is_superuser == True and request.user.company_site == serializer.data.get('company_site')) or request.user.id == serializer.data.get('id'):
            return Response(serializer.data)
        return Response({"Message" : "You don't have permission"})

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        # if instance.company_site == request.user.company_site:
        partial = kwargs.pop('partial', False)
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)
        # return Response({"Message" : "You don't have permission to update"})
    

    def perform_update(self, serializer):
        serializer.save()

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)


    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.created_by == request.user:
            self.perform_destroy(instance)
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response({"Message" : "You don't have permission to delete"})

    def perform_destroy(self, instance):
        instance.delete()
    
    def get_permissions(self):
        try:
            # return permission_classes depending on `action` 
            return [permission() for permission in self.permission_classes_by_action[self.action]]
        except KeyError: 
            # action is not set return default permission_classes
            return [permission() for permission in self.permission_classes]

    filter_backends = (filters.SearchFilter,)
    search_fields = ('name', 'email',)



class AdminCreateView(generics.CreateAPIView):
    serializer_class = serializers.AdminSerializer
    queryset = models.UserProfile.objects.all()

    template_name = 'accounts/register.html'

    authentication_classes = [TokenAuthentication]

    msg     = None
    success = False

    def get(self, request, *args, **kwargs):
        serializer = self.get_serializer()
        return render(request, self.template_name, {'form': serializer, "msg" : None, "success" : False})

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if request.data.get("password") != request.data.get("confirm_password"):
            return render(request, self.template_name, { "data": request.data, 'form': serializer, "msg" : "Password Mismatch", "success" : False})

        if serializer.is_valid():

            user = serializer.save()
            user.save()

            current_site = get_current_site(request)
            mail_subject = 'Welcome to Ticket Management System'
            message = render_to_string('admin_email.html', {
                'user': request.data.get('name'),
                'company_site' : request.data.get('company_site'),
            })
            to_email = request.data.get('email')
            email = EmailMessage(
                        mail_subject, message, to=[to_email]
            )
            email.send()

            messages.success(request, ('Admin Account Created Successfully'))

            username = request.data.get("username")
            raw_password = request.data.get("password")
            user = authenticate(username=username, password=raw_password)

            msg     = 'User created.'
            success = True
            
            login(request, user)
            return redirect("/index/")
            
            # return redirect("/login/")


            # return render(request, "accounts/register.html", {"form": serializer, "msg" : msg, "success" : success })

        return render(request, self.template_name, {"data": request.data,'form': serializer, "msg" : "Form is not valid",})

    # def post(self, request, *args, **kwargs):
    #     serializer = self.get_serializer(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     user = serializer.save()
    #     # headers = self.get_success_headers(serializer.data)
    #     return render(request, 'register.html', {'form': user})

    
    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (permissions.ProfilePermission,)


class AdminUpdateView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = serializers.AdminSerializer
    queryset =  models.UserProfile.objects.all()
    template_name = 'edit_profile.html'

    # authentication_classes = (TokenAuthentication,)
    # permission_classes = (permissions.ProfilePermission, permissions.HasAdminPermission)

    msg     = None
    success = False

    def get(self, request, *args, **kwargs):
        print(":::Get :::")
        serializer = self.get_serializer()
        return render(request, self.template_name, {'form': serializer, "msg" : None, "success" : False})

    def post(self, request, *args, **kwargs):
        print(":::Editing Started :::")
        instance = get_object_or_404(models.UserProfile, id=request.user.id)
        serializer = self.get_serializer(data=request.data, instance=instance)
        print("::: After serializer :::")

        # if serializer.is_valid():
    
        # serializer.is_valid()
        request.data._mutable = True
        user = serializer.update(instance, request.data)
        request.data._mutable = False
        user.save()
        print("user")
        print(user)
        print("user.data")
        # print(user.data)




            

        messages.success(request, ('Profile Edited Successfully'))

        msg     = None
        success = False
            
            


        return render(request, self.template_name, {"form": serializer, "msg" : msg, "success" : success })

        # return render(request, self.template_name, {"data": request.data,'form': serializer, "msg" : "Form is not valid",})




class UserLoginApiView(ObtainAuthToken):
   """Handle creating user authentication tokens"""
   renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES