# custom_middleware.py
import requests
from django.conf import settings
from django.http import HttpResponse
from rest_framework import status

from api.models import UserDB


class MdcimAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        user_db = None
        if user.is_authenticated:
            user_db = UserDB.objects.filter(user=user).first()

        except_paths = [
            '/v2/app/login',
            '/v2/app/sso-login',
            '/v2/app/logout',
            '/v2/app/refresh-token',
            '/v2/app/verify-email',
            '/v2/app/verify-phone',
            '/v2/app/forgot-password',
            '/v2/app/reset-password',
            '/v2/app/register',
            '/v2/app/verify-otp',
            '/admin'
        ]

        if user.is_authenticated and (not user.is_superuser and user_db.guid) and request.path not in except_paths and not request.path.startswith('/admin'):
            data = {
                "client_id": getattr(settings, "MDCIM_CLIENT_ID"),
                "client_secret": getattr(settings, "MDCIM_CLIENT_SECRET"),
                "redirect_uri": getattr(settings, "MDCIM_REDIRECT_URL"),
                "grant_type": "refresh_token",
                "refresh_token": user_db.refresh_token,
                "scope": "[openid|users]"
            }
            sso_url = getattr(settings, "SSO_URL")
            api_url = f'{sso_url}/v2/oauth2/token'
            response = requests.post(api_url, data=data)

            if response.ok:
                user_db.refresh_token = response.json().get('refresh_token')
                user_db.save()

            if not response.ok:
                return HttpResponse("Unauthorized", status=status.HTTP_401_UNAUTHORIZED)

        return self.get_response(request)
