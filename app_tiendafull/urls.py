from django.urls import path, include
from app_tiendafull import views
from rest_framework import routers


router = routers.DefaultRouter()

router.register(r"products", views.ProductViewSet)
router.register(r"cart", views.CartViewSet)
router.register(r"purchase", views.PurchaseViewSet)

urlpatterns = [
    path("", include(router.urls)),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("logoutall/", views.LogoutAllView.as_view(), name="logoutall"),
    path("register/", views.RegisterView.as_view(), name="register"),
]
