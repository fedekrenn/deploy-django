# Generated by Django 4.2 on 2024-10-25 22:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app_tiendafull', '0008_alter_purchase_nro_factura'),
    ]

    operations = [
        migrations.AddField(
            model_name='purchase',
            name='es_cancelada',
            field=models.BooleanField(default=False),
        ),
    ]
