from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    # path("register", views.register),
    path("login", views.login),
    path('Employee_Customer', views.Employee_Customer),
    path('Employee_register', views.Employee_register),

    path('customerscreen', views.customer_view),
    path('employeescreen', views.employee_view),

    path('auth/reset-password/<slug:authToken>', views.reset_password),


]
