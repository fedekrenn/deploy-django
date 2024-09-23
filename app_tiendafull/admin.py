from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth import get_user_model
from .models import *

# Register your models here.
admin.site.register(PaymentModeType)
admin.site.register(ColorType)
admin.site.register(StyleType)
admin.site.register(BrandType)
admin.site.register(MaterialType)
admin.site.register(WheelSizeType)
admin.site.register(Product)
admin.site.register(Cart)
admin.site.register(CartDetail)
admin.site.register(Purchase)
admin.site.register(PurchaseDetail)
admin.site.register(DeliveryStatusType)
admin.site.register(Delivery)


@admin.register(get_user_model())
class UserAdmin(UserAdmin):
    pass
