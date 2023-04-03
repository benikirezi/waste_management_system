# Generated by Django 4.1.7 on 2023-03-30 15:05

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0005_alter_user_user_type"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="userlocation",
            name="national_id",
        ),
        migrations.RemoveField(
            model_name="userlocation",
            name="phone_number",
        ),
        migrations.RemoveField(
            model_name="userlocation",
            name="second_number",
        ),
        migrations.AddField(
            model_name="user",
            name="national_id",
            field=models.CharField(default="", max_length=200),
        ),
        migrations.AddField(
            model_name="user",
            name="phone_number",
            field=models.CharField(default="", max_length=200),
        ),
        migrations.AddField(
            model_name="user",
            name="second_number",
            field=models.CharField(default="", max_length=200),
        ),
    ]
