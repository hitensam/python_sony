import re

from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from rest_framework.authtoken.models import Token


class VersionCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        meta = request.META.get('HTTP_REFERER', "")
        if re.search(r"\/app\/", request.path) and not(re.search(r"\/portal\/", meta)):
            if 'v2' not in request.path and '/profile' not in request.path:
                return JsonResponse({"status": "Failed", "message": "Please update your app to the latest version to proceed"}, status=403)

        response = self.get_response(request)
        return response


class XApiKeyCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        meta = request.headers.get('X-Api-Key', "")
        if request.path == "/v2/app/user-details":
            if meta:
                try:
                    token_data = Token.objects.get(key=meta)
                    user = token_data.user
                    if user.user_permissions.all()[0].name == "CMS user permissions":
                        response = self.get_response(request)
                        return response
                    else:
                        return JsonResponse({"status": "Failed", "message": "User does not have permission to access this resource"}, status=401)

                except ObjectDoesNotExist:
                    return JsonResponse({"status": "Failed", "message": "Invalid X-Api-Key"}, status=401)
            else:
                return JsonResponse({"status": "Failed", "message": "Please pass X-Api-Key to access this resource"}, status=401)

        response = self.get_response(request)
        return response
