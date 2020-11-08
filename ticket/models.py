from django.db import models
try:
    from django.utils import timezone
except ImportError:
    from datetime import datetime as timezone
from django.conf import settings    
# Create your models here.



class Ticket(models.Model):
    STATUS_CHOICES = (
        ('New','New'),
        ('InProgress','InProgress'),
        ('Resolved','Resolved'),
    )
    PRIOIRTY_CHOICES =(
        ('Low','Low'),
        ('Medium','Medium'),
        ('High','High'),
        ('Urgent','Urgent'),
    )
    CREATED_CHOICES = (
        ('Admin','Admin'),
        ('Agent','Agent'),
        
    )
    subject = models.CharField(max_length=255)
    description = models.TextField(blank=True,null=True)
    status = models.CharField(choices=STATUS_CHOICES,default='NULL',max_length=250)
    priority = models.CharField(choices=PRIOIRTY_CHOICES,max_length=100,default='Low')
    #contact = models.ManyToOneRel(Customer,on_delete=models.SET_NUL,blank=True,null=True)
    contact = models.EmailField(max_length=250,blank=True,null=True)
    assigned_to =models.ForeignKey(settings.AUTH_USER_MODEL,related_name="agents",blank=True,null=True,on_delete=models.SET_NULL,)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL,related_name="users",choices=CREATED_CHOICES,blank=True,null=True,on_delete=models.SET_NULL)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    

    def __str__(self):
        return self.subject


class Customer(models.Model):
    email = models.EmailField(max_length=70,blank=True,unique=True)
    first_name = models.CharField(max_length=250,blank=True)
    last_name = models.CharField(max_length=250,blank=True)
    ticket = models.ForeignKey(Ticket,blank=True,null=True,on_delete=models.SET_NULL)

 

    def __str__(self):
        return self.email

    # def save(self, *args, **kwargs):
    #     self.email = self.email.lower().strip() # Hopefully reduces junk to ""
    #     if self.email != "": # If it's not blank
    #         if not email_re.match(self.email) # If it's not an email address
    #         raise ValidationError(u'%s is not an email address, dummy!' % self.email)
    #     if self.email == "":
    #         self.email = None
    #     super(Customer, self).save(*args, **kwargs)