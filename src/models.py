from django.db import models
from django.contrib.auth.models import AbstractUser
from django_otp.models import Device
from django.dispatch import receiver
from django.db.models.signals import post_save

# Create your models here.


class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ("Customer", "Customer"),
        ("Employee", "Employee"),
        ("Admin", "Admin"),
    )

    gender = (
        ("Male",'Male'),
        ("Female",'Female'),
        ("Others",'Others'),
    )

    user_type = models.CharField(max_length=200,choices=USER_TYPE_CHOICES, default="CUSTOMER")
    otp_enabled = models.BooleanField(default=False)
    phone_number = models.CharField(max_length=200,default="")
    second_number = models.CharField(max_length=200,default="")
    national_id = models.CharField(max_length=200,default="")
    province = models.CharField(max_length=200,default="")
    district = models.CharField(max_length=200,default="")
    sector = models.CharField(max_length=200,default="")
    cell = models.CharField(max_length=200,default="")
    property_number = models.CharField(max_length=200, default="")
    gender = models.CharField(max_length=200,choices=gender, default=1)
    age = models.IntegerField(default=1)

@receiver(post_save, sender=User)
def create_user_otp(sender, instance, created, **kwargs):
    if created:
        OTP.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_otp(sender, instance, **kwargs):
    instance.otp.save()



class OTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    email_otp_enabled = models.BooleanField(default=False)

    @property
    def email_device(self):
        try:
            return self.user.devices.get(name='email')
        except Device.DoesNotExist:
            return None

    def verify_email_otp(self, token):
        if self.email_device:
            return self.email_device.verify_token(token)
        return False

    def enable_email_otp(self):
        if not self.email_otp_enabled:
            device = EmailDevice.objects.create(name='email', user=self.user, 
                                                 email=self.user.email)
            self.email_otp_enabled = True
            self.save()
            return device

    def disable_email_otp(self):
        if self.email_otp_enabled:
            if self.email_device:
                self.email_device.delete()
            self.email_otp_enabled = False
            self.save()
