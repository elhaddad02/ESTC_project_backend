from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed, InvalidToken

class BaseAuthenticatedPermission(BasePermission):
    """
    Base permission class to check if a user is authenticated and has a specific role.
    """

    def has_permission(self, request, view):
        """
        Check if the request has permission.

        Args:
            request (HttpRequest): The request object.
            view (View): The view object.

        Returns:
            bool: True if the user has permission, False otherwise.
        """
        user = self.get_user(request)
        if not user or user.is_anonymous:
            return False
        return self.check_role(user)

    def get_user(self, request):
        """
        Attempt to authenticate the user.

        Args:
            request (HttpRequest): The request object.

        Returns:
            User or None: The authenticated user or None if authentication fails.
        """
        jwt_auth = JWTAuthentication()
        try:
            user, _ = jwt_auth.authenticate(request)
            return user
        except (AuthenticationFailed, InvalidToken):
            return None

    def check_role(self, user):
        """
        This method should be overridden in subclasses to check for specific roles.

        Args:
            user (User): The user object.

        Returns:
            bool: True if the user has the required role, False otherwise.
        """
        return user.is_authenticated

class IsStudentAuthenticated(BaseAuthenticatedPermission):
    """
    Permission class to check if a user is authenticated and is a student.
    """
    def check_role(self, user):
        """
        Check if the user has the 'student' role.

        Args:
            user (User): The user object.

        Returns:
            bool: True if the user has the 'student' role, False otherwise.
        """
        return user.is_authenticated and user.role == 'student'

class IsParentAuthenticated(BaseAuthenticatedPermission):
    """
    Permission class to check if a user is authenticated and is a parent.
    """
    def check_role(self, user):
        """
        Check if the user has the 'parent' role.

        Args:
            user (User): The user object.

        Returns:
            bool: True if the user has the 'parent' role, False otherwise.
        """
        return user.is_authenticated and user.role == 'parent'

class IsPartnerAuthenticated(BaseAuthenticatedPermission):
    """
    Permission class to check if a user is authenticated and is a partner.
    """
    def check_role(self, user):
        """
        Check if the user has the 'partner' role.

        Args:
            user (User): The user object.

        Returns:
            bool: True if the user has the 'partner' role, False otherwise.
        """
        return user.is_authenticated and user.role == 'partner'

class IsAdministratorAuthenticated(BaseAuthenticatedPermission):
    """
    Permission class to check if a user is authenticated and is an administrator.
    """
    def check_role(self, user):
        """
        Check if the user has the 'admin' role.

        Args:
            user (User): The user object.

        Returns:
            bool: True if the user has the 'admin' role, False otherwise.
        """
        return user.is_authenticated and user.role == 'admin'
