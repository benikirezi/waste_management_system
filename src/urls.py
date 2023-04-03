from django.contrib import admin
from django.urls import path, include
from . import views
from knox import views as knox_views



urlpatterns = [
    # path("register", views.register),
    path("login", views.login),
    path('Employee_Customer', views.Employee_Customer),
    path('Employee_register', views.Employee_register),

    path('customerscreen', views.customer_view),
    path('employeescreen', views.employee_view),
    path('logout', knox_views.LogoutView.as_view(), name='knox_logout'),
    path('logoutall', knox_views.LogoutAllView.as_view(), name='knox_logoutall'),

    path('auth/reset-password/<slug:authToken>', views.reset_password),


]
