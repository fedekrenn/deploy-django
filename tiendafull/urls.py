
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    # Api routes
    path("api/", include("app_tiendafull.urls")),
    
]
