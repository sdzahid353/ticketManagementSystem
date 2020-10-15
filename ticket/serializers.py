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
            assigned_to=validated_data['assigned_to'],
            created_by=self.context["request"].user
        )

        return ticket


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Customer
        fields = '__all__'