from django.apps import AppConfig


class AppTiendafullConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "app_tiendafull"

    def ready(self):
        import  app_tiendafull.signals