from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import Delivery, Purchase

@receiver(post_save, sender=Purchase)
def create_delivery(sender, instance, created, **kwargs):
    if created:
        Delivery.objects.create(
            compra=instance,
            nro_seguimiento="11111",
            domicilio_entrega="alguno",
            fecha_estimada="2029-12-31"
        )
