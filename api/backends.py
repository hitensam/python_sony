from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User

from api.models import UserDB


class EmailAuthBackend(ModelBackend):
    def get_user(self, user_id):
        """
        Modify existing get_user method to fetch the user details with email
        """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def authenticate(self, request, username, password, **kwargs):
        UserModel = get_user_model()
        online_flag = kwargs.get('online', False)
        try:
            if online_flag:
                user = UserModel.objects.get(username=username)
                user_details = UserDB.objects.get(user=user)
                if user_details.user_type != "online":
                    user = None
            else:
                user = UserModel.objects.get(email=username)
        except UserModel.DoesNotExist:
            return None
        if user.check_password(password):
            return user
        return None
