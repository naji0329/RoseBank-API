# Generated by Django 4.2.2 on 2023-06-08 06:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Account', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user_otp',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]
