from rest_framework.permissions import BasePermission


class IsEmailVerified(BasePermission):
    """
    Custom permission class to restrict access to users with verified email addresses.
    """

    def has_permission(self, request, view):
        user = request.user
        if user.is_authenticated and user.emailaddress_set.filter(verified=True).exists():
            # Allow access if the user is authenticated and has at least one verified email address.
            return True
        else:
            # Deny access if the user is not authenticated or has no verified email address.
            return False
