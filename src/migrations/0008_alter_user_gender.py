# Generated by Django 4.1.7 on 2023-03-30 15:24

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("src", "0007_remove_userlocation_cell_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="gender",
            field=models.CharField(
                choices=[("Male", "Male"), ("Female", "Female"), ("Others", "Others")],
                default=1,
                max_length=200,
            ),
        ),
    ]
