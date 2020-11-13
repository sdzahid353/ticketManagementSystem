from rest_framework import serializers

from . import models


class TicketSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = models.Ticket
        fields = '__all__'

        extra_kwargs = {
            'created_by' : {
                'read_only' : True
            }
        }

    def create(self, validated_data):
        """Create and return a new admin"""
        ticket = models.Ticket.objects.create(
            subject=validated_data['subject'],
            description=validated_data['description'],
            status=validated_data['status'],
            contact=validated_data['contact'],
            priority=validated_data['priority'],
            assigned_to=validated_data['assigned_to'],
            created_by=self.context["request"].user
        )

        return ticket


class TicketUpdateSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = models.Ticket
        fields = '__all__'

        extra_kwargs = {
            'contact' : {
                'read_only' : True,
            },    
            'assigned_to': {
                'read_only' : True
            }
        }
  
    def update(self, instance, validated_data):
        """Handle updating agent account"""
      
        if validated_data['subject'] == '':
            validated_data['subject'] = instance.subject
        if validated_data['description'] == '':
            validated_data['description'] = instance.description
        if validated_data['status'] == '':
            validated_data['status'] = instance.status
        if validated_data['priority'] == '':
            validated_data['priority'] = instance.priority   

        return super().update(instance, validated_data)



class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Customer
        fields = '__all__'