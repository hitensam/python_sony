import decimal
import json
import math
import re
from datetime import date, datetime, timedelta

import requests
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django import utils
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.models import Permission, User
from django.contrib.auth.tokens import default_token_generator
from django.core import serializers
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import EmailMultiAlternatives, send_mail
from django.db.models import Sum
from django.template import Context
from django.template.loader import get_template, render_to_string
from django.utils.crypto import get_random_string
from django.utils.encoding import force_text
from rest_framework import permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView

from cms.models import FaqDB, OfferCategoryDB, OffersDB, ProductDB

from .helpers import (AlphaLogin, RetrieveOTP, StoreVoucherCode, VerifyOtp,
                      log_user_points_webengage, online_sync_points,
                      user_identifier, webengage_log_events)
from .models import (AppConfigDB, EnabledCountriesDB, PointsDB, TransactionDB,
                     UserDB, VoucherCodeDB)
from .serializers import TransactionSerializer, UserSerializer


class RegisterAPI(APIView):
    """
    APIview which will deposit the transaction
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request):
        """
        POST method which will create a new user to the app hence registering them to
        the loyalty app
        """
        try:
            username = get_random_string(length=10)
            request.data["username"] = username
            user_type = request.data["user_type"].lower()
            user_serializer = UserSerializer(data=request.data)
            permission_name = ""
            country = request.data["country"].upper()
            if EnabledCountriesDB.objects.filter(country_code=country).exists():
                return Response(
                    {"status": "Failed", "message": "You should signup using MDCIM api's."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if user_serializer.is_valid():
                user = user_serializer.create(user_serializer.validated_data)
                if user:
                    token = Token.objects.create(user=user)
                    points = PointsDB.objects.create(user=user)
                    if user_type == "app":
                        permission_name = "App user permissions"
                    elif user_type == "cms":
                        permission_name = "CMS user permissions"
                    elif user_type == "store":
                        permission_name = "Store user permissions"
                    elif user_type == "google":
                        permission_name = "App user permissions"
                    elif user_type == "facebook":
                        permission_name = "App user permissions"
                    permission = Permission.objects.get(name=permission_name)
                    user.user_permissions.add(permission)
                    user.save()
                    json = user_serializer.data
                    json["token"] = token.key
                    if user_type not in ["cms", "store"]:
                        user_name = user.first_name
                        email = user.email
                        email_text = render_to_string(
                            "welcome-template/welcome-template.txt",
                            {"username": user_name},
                        )
                        email_html = render_to_string(
                            "welcome-template/welcome-template.html",
                            {"username": user_name},
                        )
                        send_mail(
                            subject="Welcome to Sony Loyalty Program",
                            message=email_text,
                            recipient_list=[email],
                            from_email=None,
                            html_message=email_html,
                        )
                    reg_event_data = {
                        "userId": user.email,
                        "eventName": "User Registered",
                        "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                        "eventData": {
                            "First Name": user.first_name,
                            "Last Name": user.last_name,
                            "Email Address": user.email,
                        },
                    }
                    user_data = {
                        "userId": user.email,
                        "firstName": user.first_name,
                        "lastName": user.last_name,
                        "attributes": {
                            "Subscribed to news letter": False,
                            "Rewards Balance": 0,
                            "Total No.of Transactions": 0,
                            "Total No.of Earned Points": 0,
                            "Total No.of Redeemed points": 0,
                            "Earned Product List": "",
                            "Redeemed Products List": "",
                        },
                    }
                    webengage_log_events(user_data, "user")
                    webengage_log_events(reg_event_data, "events")
                    return Response(
                        {
                            "status": "Success",
                            "message": "User registered successfully",
                        },
                        status=status.HTTP_201_CREATED,
                    )
            else:
                user = User.objects.get(email=request.data["email"])
                user_details = UserDB.objects.get(user=user)
                return Response(
                    {
                        "status": "Failed",
                        "message": "User account already exists in system",
                        "user_type": user_details.user_type,
                    },
                    status=status.HTTP_409_CONFLICT,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @staticmethod
    def get(request):
        """
        GET method which will fetch the details of a user who has registered with the app.
        Used for internal testing
        """
        try:
            email = request.GET["email"]
            user = User.objects.get(email=email)
            if user is not None:
                return Response(
                    {
                        "status": "Success",
                        "message": "Fetched user data successfully",
                        "data": {
                            "username": user.username,
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                            "password": user.password,
                        },
                    },
                    status=status.HTTP_200_OK,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EmailCheckAPI(APIView):
    """
    APIView which will check if a user has registered with the loyalty app
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request):
        """
        POST method which will check if a user has registered with the loyalty app
        """
        try:
            email = request.data["email"]
            user = User.objects.get(email=email)
            user_db = UserDB.objects.get(user__email=email)
            user_linked = EnabledCountriesDB.objects.filter(country_code=user_db.country).exists()
            if user is not None:
                return Response(
                    {
                        "status": "Success", "message": "User exists in system",
                        "data": {
                            "country_exist": True if user_db.country else False,
                            "country": user_db.country,
                            "should_user_link": True if user_linked and not user_db.guid else False,
                        }
                    },
                    status=status.HTTP_200_OK,
                )
        except ObjectDoesNotExist:
            return Response(
                {"status": "Failed", "message": "User does not exist in system"},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class CountryCheckAPI(APIView):
    """
    APIView which will check if a country is enabled for MDCIM with the loyalty app
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request):
        """
        POST method which will check if a user has registered with the loyalty app
        """
        try:
            country = (request.data["country"]).upper()
            country = EnabledCountriesDB.objects.get(country_code=country)
            # user_country = UserDB.objects.get(user__email=request.data["email"]).country
            if country is not None:
                return Response(
                    {"status": "Success", "message": "Country is enabled"},
                    status=status.HTTP_200_OK,
                )
        except ObjectDoesNotExist:
            return Response(
                {"status": "Failed", "message": "Country is not enabled"},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LoginAPI(APIView):
    """
    API which will log the user to the app
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request):
        """
        POST method which will login the user to the loyalty app
        """
        try:
            email = request.data["email"]
            password = request.data["password"]
            user = authenticate(request, username=email, password=password)
            token = None
            if user is not None:
                user_db = UserDB.objects.get(user=user)
                if (
                    user_db.user_type == "alpha"
                    or user_db.user_type == "google"
                    or user_db.user_type == "facebook"
                ):
                    return Response(
                        {
                            "status": "Failed",
                            "message": "Incorrect email address or password.",
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )
                # if user_db.country is None and request.data.get("country") is None and user_db.user_type=="app":
                #     return Response({
                #         "status": "Failed",
                #         "message": "Please provide country to login",
                #     })
                login(request, user)
                try:
                    token = Token.objects.get(user=user)
                except ObjectDoesNotExist:
                    token = Token.objects.create(user=user)

                if user_db.country is None and request.data.get("country"):
                    user_db.country = request.data["country"]
                    user_db.save()

                if request.data.get("nationality"):
                    user_db.nationality = request.data["nationality"]
                    user_db.save()

                country_enabled = EnabledCountriesDB.objects.filter(country_code=user_db.country).exists()
                mdcim_popup = False
                if user_db.guid is None and country_enabled:
                    mdcim_popup = True

                login_event_data = {
                    "userId": user.email,
                    "eventName": "User Signed In",
                    "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                    "eventData": {"Email": user.email},
                }
                webengage_log_events(login_event_data, "events")

                log_user_points_webengage(user)

                return Response(
                    {
                        "status": "Success",
                        "message": "User logged in successfully",
                        "data": {
                            "user_id": user.id,
                            "username": user.username,
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                            "email": user.email,
                            "token": token.key,
                            "user_type": user_db.user_type,
                            "country": user_db.country,
                            "nationality": user_db.nationality,
                            "mdcim_popup": mdcim_popup,
                            "mdcim_user": True if user_db.guid else False
                        },
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "status": "Failed",
                        "message": "Incorrect email address or password.",
                    },
                    status=status.HTTP_404_NOT_FOUND,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AlphaUniverseAPI(APIView):
    """
    APIView which will register/login an alpha universe user to the loyalty app
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request):
        """
        POST method which will login/register an alpha universe user to the loyalty app
        """
        try:
            email = request.data["email"]
            password = request.data["password"]
            user = authenticate(request, username=email, password=password)
            token = None
            if user is not None:
                user_db = UserDB.objects.get(user=user)
                if user_db.user_type != "alpha":
                    return Response(
                        {
                            "status": "Failed",
                            "message": "Incorrect email address or password.",
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )
                login(request, user)
                try:
                    token = Token.objects.get(user=user)
                except ObjectDoesNotExist:
                    token = Token.objects.create(user=user)
                return Response(
                    {
                        "status": "Success",
                        "message": "User logged in successfully",
                        "data": {
                            "user_id": user.id,
                            "username": user.username,
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                            "email": user.email,
                            "token": token.key,
                            "user_type": user_db.user_type,
                        },
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                user_details = AlphaLogin(email, password)
                if user_details["status"]:
                    username = get_random_string(length=10)
                    user_data = {
                        "username": username,
                        "first_name": user_details["response"]["data"]["display_name"],
                        "last_name": user_details["response"]["data"]["display_name"],
                        "email": user_details["response"]["data"]["user_email"],
                        "user_type": "alpha",
                        "password": password,
                    }
                    user_serializer = UserSerializer(data=user_data)
                    if user_serializer.is_valid():
                        user = user_serializer.create(user_serializer.validated_data)
                        if user:
                            permission_name = "App user permissions"
                            token = Token.objects.create(user=user)
                            points = PointsDB.objects.create(user=user)
                            permission = Permission.objects.get(name=permission_name)
                            user.user_permissions.add(permission)
                            user.save()
                            json = user_serializer.data
                            json["token"] = token.key
                            login(
                                request, user, backend="api.backends.EmailAuthBackend"
                            )
                            return Response(
                                {
                                    "status": "Success",
                                    "message": "User logged in successfully",
                                    "data": {
                                        "user_id": user.id,
                                        "username": user.username,
                                        "first_name": user.first_name,
                                        "last_name": user.last_name,
                                        "email": user.email,
                                        "token": token.key,
                                        "user_type": user_data["user_type"],
                                    },
                                },
                                status=status.HTTP_200_OK,
                            )
                    else:
                        user = User.objects.get(email=request.data["email"])
                        if user is not None:
                            user_details = UserDB.objects.get(user=user)
                            return Response(
                                {
                                    "status": "Failed",
                                    "message": "User account already exists in system",
                                    "user_type": user_details.user_type,
                                },
                                status=status.HTTP_409_CONFLICT,
                            )
                        else:
                            return Response(
                                user_serializer.errors, status=status.HTTP_404_NOT_FOUND
                            )
                else:
                    return Response(
                        {
                            "status": "Failed",
                            "message": "Invalid Alpha Universe Credentials",
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ChangePasswordAPI(APIView):
    """
    APIView which will change the password of the user using the loyalty app
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    def put(request):
        """
        PUT method which will change the password of a user
        """
        try:
            user = User.objects.get(id=request.user.id)
            old_password = request.data["current_password"]
            new_password = request.data["new_password"]
            if user.check_password(old_password):
                if not new_password:
                    return Response(
                        {"status": "Failed", "message": "Password should not be empty"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                else:
                    user.set_password(new_password)
                    user.save()
                    user_name = user.first_name
                    email = user.email
                    email_text = render_to_string(
                        "pass-change-confirmation/pass-change-template.txt",
                        {"username": user_name},
                    )
                    email_html = render_to_string(
                        "pass-change-confirmation/pass-change-template.html",
                        {"username": user_name},
                    )
                    send_mail(
                        subject="Password Reset Confirmation",
                        message=email_text,
                        recipient_list=[email],
                        from_email=None,
                        html_message=email_html,
                    )
                    new_pass_data = {
                        "userId": email,
                        "eventName": "New Password Created",
                        "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                        "eventData": {"Status": True},
                    }
                    webengage_log_events(new_pass_data, "events")
                    return Response(
                        {
                            "status": "Success",
                            "message": "Password changed successfully",
                        },
                        status=status.HTTP_200_OK,
                    )
            else:
                return Response(
                    {
                        "status": "Failed",
                        "message": "The entered password is incorrect",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ForgetPasswordChangeAPI(APIView):
    """
    APIView which will change a users password if they forget their password
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def put(request):
        """
        PUT method which will change a users password if they forget their password
        """
        try:
            uidb64 = request.data["uidb64"]
            token = request.data["token"]
            password = request.data["password"]
            uid = force_text(utils.http.urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            user_name = user.first_name
            user_email = user.email
            if user and default_token_generator.check_token(user=user, token=token):
                user.set_password(password)
                user.save()
                email_text = render_to_string(
                    "pass-change-confirmation/pass-change-template.txt",
                    {"username": user_name},
                )
                email_html = render_to_string(
                    "pass-change-confirmation/pass-change-template.html",
                    {"username": user_name},
                )
                send_mail(
                    subject="Password Reset Confirmation",
                    message=email_text,
                    recipient_list=[user_email],
                    from_email=None,
                    html_message=email_html,
                )
                reset_pass_data = {
                    "userId": user_email,
                    "eventName": "Reset Password Confirmed",
                    "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                    "eventData": {"Email": user_email},
                }
                webengage_log_events(reset_pass_data, "events")
                return Response(
                    {"status": "Success", "message": "Password changed successfully"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "status": "Failed",
                        "message": "Password reset failed. Please contact administrator",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ProfileAPI(APIView):
    """
    APIView which will fetch a users profile details
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    def get(request):
        """
        GET method which will fetch a users profile details
        """
        try:
            user = User.objects.get(username=request.user.username)
            user_details = UserDB.objects.get(user=user)
            return Response(
                {
                    "status": "Success",
                    "data": {
                        "username": user.username,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "email": user.email,
                        "promotion_consent": user_details.promotion_consent,
                    },
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @staticmethod
    def put(request):
        """
        PUT method which will update a users profile data
        """
        try:
            user = User.objects.get(username=request.user.username)
            user_details = UserDB.objects.get(user=user)
            update_param = request.data
            update_data = {}
            for key, value in update_param.items():
                if key != "username" and key != "email":
                    setattr(user, key, value)
                if key == "promotion_consent":
                    setattr(user_details, key, value)
                    promotion_consent_event_data = {
                        "userId": user.email,
                        "eventName": "Subscribed to email updates",
                        "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                        "eventData": {},
                    }
                    webengage_log_events(promotion_consent_event_data, "events")
                    user_details.save()
                if value:
                    if key == "email":
                        update_data["Email id"] = value
                    if key == "first_name":
                        update_data["First Name"] = value
                    if key == "last_name":
                        update_data["Last Name"] = value

            user.save()
            if update_data:
                profile_update_data = {
                    "userId": request.user.email,
                    "eventName": "Profile Updated",
                    "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                    "eventData": update_data,
                }
                webengage_log_events(profile_update_data, "events")
                log_user_points_webengage(user)
            return Response(
                {"status": "Success", "message": "User profile has been updated"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class LogoutAPI(APIView):
    """
    APIView which will logout the user from the loyalty app
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    def post(request):
        """
        POST method which will logout the user from the loyalty app
        """
        try:
            user_data = request.user
            request.user.auth_token.delete()
            logout(request)
            logout_event_data = {
                "userId": user_data.email,
                "eventName": "User Signed Out",
                "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                "eventData": {"Email": user_data.email},
            }
            webengage_log_events(logout_event_data, "events")
            return Response(
                {"status": "Success", "message": "Successfully logged out"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class SendOtpAPI(APIView):
    """
    APIView which will send the otp to the user using the loyalty app
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request):
        """
        POST method which will send otp to a user of the loyalty app
        """
        try:
            email = request.data["email"]
            otp_type = request.data["otp_type"]
            otp_generate = RetrieveOTP(email, otp_type)
            if otp_generate["status"] == "Success":
                user_name = otp_generate["data"]["first_name"]
                otp = otp_generate["data"]["otp"]
                if otp_type == "forget-password":
                    email_text = render_to_string(
                        "forget-password/otp-template.txt",
                        {"username": user_name, "otp": otp},
                    )
                    email_html = render_to_string(
                        "forget-password/otp-template.html",
                        {"username": user_name, "otp": otp},
                    )
                    send_mail(
                        subject="Password Reset OTP",
                        message=email_text,
                        recipient_list=[email],
                        from_email=None,
                        html_message=email_html,
                    )
                elif otp_type == "verification":
                    email_text = render_to_string(
                        "email-verification/verify-email-template.txt",
                        {"username": user_name, "otp": otp},
                    )
                    email_html = render_to_string(
                        "email-verification/verify-email-template.html",
                        {"username": user_name, "otp": otp},
                    )
                    send_mail(
                        subject="Verification OTP",
                        message=email_text,
                        recipient_list=[email],
                        from_email=None,
                        html_message=email_html,
                    )
                return Response(
                    {"status": "Success", "message": "OTP sent to user's email"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"status": "Failed", "message": otp_generate["message"]},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        except Exception as e:
            print(e)  # Debug statement
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class VerifyOtpAPI(APIView):
    """
    APIView used to verify an account before registering with the loyalty app
    """

    @staticmethod
    def post(request):
        """
        POST method which will verify the otp user types from their email to verify their
        account
        """
        try:
            otp = request.data["otp"]
            otp_type = request.data["otp_type"]
            otp_status = VerifyOtp(otp, otp_type)
            if otp_status["status"] == "Success":
                if otp_type == "forget-password":
                    pass_change_data = user_identifier(otp_status["data"]["email"])
                    if pass_change_data["status"] == "Success":
                        otp_verify_data = {
                            "userId": otp_status["data"]["email"],
                            "eventName": "OTP Verified",
                            "eventTime": datetime.now().strftime(
                                "%Y-%m-%dT%H:%M:%S+0400"
                            ),
                            "eventData": {"Status": True},
                        }
                        webengage_log_events(otp_verify_data, "events")
                        return Response(
                            {
                                "status": "Success",
                                "message": "Otp verfication successful",
                                "data": {
                                    "token": pass_change_data["data"]["token"],
                                    "uidb64": pass_change_data["data"]["uidb64"],
                                },
                            },
                            status=status.HTTP_200_OK,
                        )
                    else:
                        return Response(
                            {
                                "status": "Failed",
                                "message": pass_change_data["message"],
                            },
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        )
                else:
                    user_data = request.data["user_info"]
                    if user_data:
                        otp_verify_data = {
                            "userId": request.data["user_info"]["email"],
                            "eventName": "OTP Verified",
                            "eventTime": datetime.now().strftime(
                                "%Y-%m-%dT%H:%M:%S+0400"
                            ),
                            "eventData": {"Status": True},
                        }
                        webengage_log_events(otp_verify_data, "events")
                        request.data["first_name"] = request.data["user_info"][
                            "first_name"
                        ]
                        request.data["last_name"] = request.data["user_info"][
                            "last_name"
                        ]
                        request.data["password"] = request.data["user_info"]["password"]
                        request.data["email"] = request.data["user_info"]["email"]
                        request.data["country"] = request.data["user_info"]["country"]
                        request.data["nationality"] = request.data["user_info"]["nationality"]
                        request.data["user_type"] = request.data["user_info"][
                            "user_type"
                        ]
                        register_view = RegisterAPI()
                        register_resp = register_view.post(request)
                        return register_resp
                    else:
                        return Response(
                            {
                                "status": "Success",
                                "message": "User registeration failed",
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                        )

            else:
                return Response(
                    {"status": "Failed", "message": otp_status["message"]},
                    status=status.HTTP_404_NOT_FOUND,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class FCMTokenAPI(APIView):
    """
    APIView which will store the FCM token assigned by Firebase to users of loyalty app
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def post(request):
        """
        POST Method which will store the FCM token generated by a user's loyalty app
        """
        try:
            token = request.data["fcm_token"]
            user_data = UserDB.objects.get(user=request.user.id)
            user_data.fcm_token = token
            user_data.save()
            return Response(
                {"status": "Success", "message": "Token added for user account"},
                status=status.HTTP_200_OK,
            )
        except ObjectDoesNotExist as ex:
            return Response(
                {
                    "status": "Failed",
                    "message": "Unable to retrieve user data from system",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GetProductAPI(APIView):
    """
    APIView which will fetch a list of products to be displayed at the loyalty app
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def get(request):
        """
        GET method which will get retreive a list of products from the db
        """
        try:
            product_info = serializers.serialize("json", ProductDB.objects.all())
            data = json.loads(product_info)
            product_fields = []
            for i in data:
                if not i["fields"]["disable_product"]:
                    temp_data = {}
                    temp_data["id"] = i["pk"]
                    temp_data["product_info"] = i["fields"]
                    if i["fields"]["image"]:
                        image_link = settings.MEDIA_URL + i["fields"]["image"]
                        temp_data["product_info"]["image"] = image_link
                    if i["fields"]["price"]:
                        temp_data["product_info"]["price"] = float(i["fields"]["price"])
                    product_fields.append(temp_data)
            if product_fields == []:
                return Response(
                    {"status": "Failed", "message": "No offers available currently"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            else:
                return Response(
                    {"status": "Success", "data": product_fields},
                    status=status.HTTP_200_OK,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GetOffersAPI(APIView):

    """
    APIView which will fetch the offers from OfferDB and display it on the sony loyalty app
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def get(request):
        """
        GET method which will fetch the offers from OfferDB and display it on the sony loyalty app
        """

        try:
            offers_info = serializers.serialize("json", OffersDB.objects.all())
            data = json.loads(offers_info)
            offer_fields = []
            for i in data:
                if not i["fields"]["disable_offer"]:
                    temp_data = {}
                    temp_data["id"] = i["pk"]
                    temp_data["offer_info"] = i["fields"]
                    category_id = i["fields"]["category"]
                    category_details = OfferCategoryDB.objects.get(id=category_id)
                    category_name = category_details.category_name
                    temp_data["offer_info"]["category"] = {
                        "id": category_id,
                        "name": category_name,
                    }
                    temp_data["offer_info"]["images"] = []
                    if i["fields"]["image_1"]:
                        image_link = settings.MEDIA_URL + i["fields"]["image_1"]
                        temp_data["offer_info"]["images"].append(image_link)
                        del temp_data["offer_info"]["image_1"]
                    if i["fields"]["image_2"]:
                        image_link = settings.MEDIA_URL + i["fields"]["image_2"]
                        temp_data["offer_info"]["images"].append(image_link)
                        del temp_data["offer_info"]["image_2"]
                    if i["fields"]["image_3"]:
                        image_link = settings.MEDIA_URL + i["fields"]["image_3"]
                        temp_data["offer_info"]["images"].append(image_link)
                        del temp_data["offer_info"]["image_3"]
                    offer_fields.append(temp_data)
            if offer_fields == []:
                return Response(
                    {"status": "Failed", "message": "No offers available currently"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            else:
                return Response(
                    {"status": "Success", "data": offer_fields},
                    status=status.HTTP_200_OK,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class FilterOfferByCategoryAPI(APIView):
    """
    APIView which will filter offer by category and display it on the loyalty app
    """

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def get(request):
        """
        GET method which will filter offers by the category id and display it on the app
        """
        try:
            category_id = request.GET["id"]
            offers = OffersDB.objects.filter(category=category_id)
            offer_data = []
            for i in offers:
                offer_temp = {}
                if not i.disable_offer:
                    offer_temp["category"] = {
                        "id": i.category.id,
                        "name": i.category.category_name,
                    }
                    offer_temp["name"] = i.name
                    offer_temp["description"] = i.description
                    offer_temp["offer_start_date"] = i.offer_start_date
                    offer_temp["offer_end_date"] = i.offer_end_date
                    offer_temp["image_1"] = i.image_1.url
                    offer_temp["image_2"] = i.image_2.url
                    offer_temp["image_3"] = i.image_3.url
                offer_data.append(offer_temp)
                if offer_data == []:
                    return Response(
                        {
                            "status": "Failed",
                            "message": "No offers available currently for the category",
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )
                else:
                    return Response(
                        {"status": "Success", "data": offer_data},
                        status=status.HTTP_200_OK,
                    )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GetCategoryAPI(APIView):
    """
    APIView which will get list of category from db
    """

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def get(request):
        """
        GET Method which will fetch the list of category from db
        """
        try:
            category_info = serializers.serialize("json", OfferCategoryDB.objects.all())
            data = json.loads(category_info)
            category_fields = []
            for i in data:
                if not i["fields"]["disable_category"]:
                    offer_count = OffersDB.objects.filter(id=i["pk"]).count()
                    if offer_count > 0:
                        temp_data = {}
                        temp_data["id"] = i["pk"]
                        temp_data["category_name"] = i["fields"]["category_name"]
                        if i["fields"]["icon"]:
                            icon_link = settings.MEDIA_URL + i["fields"]["icon"]
                            temp_data["icon"] = icon_link
                        category_fields.append(temp_data)
            if category_fields == []:
                return Response(
                    {"status": "Failed", "message": "No offers available currently"},
                    status=status.HTTP_404_NOT_FOUND,
                )
            else:
                return Response(
                    {"status": "Success", "data": category_fields},
                    status=status.HTTP_200_OK,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GetFaqAPI(APIView):
    """
    APIView which will fetch a list of faq's from the db and display it to the app
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def get(request):
        """
        GET Method which will fetch the list of faq's from the db and show it on the app
        """
        try:
            faq_info = serializers.serialize("json", FaqDB.objects.all())
            data = json.loads(faq_info)
            faq_fields = []
            for i in data:
                if not i["fields"]["disable_faq"]:
                    temp_data = {}
                    temp_data["id"] = i["pk"]
                    temp_data["faq_details"] = i["fields"]
                    faq_fields.append(temp_data)
            return Response(
                {"status": "Success", "data": faq_fields}, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class PointsAPI(APIView):
    """
    APIView which will update/get points for a user using the loyalty app (update is used in earn scenario)
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def get(request):
        """
        GET method which will get the points a user has in their account
        """
        try:
            user = User.objects.get(id=request.user.id)
            point_details = PointsDB.objects.get(user=user)
            if point_details:
                loyalty_points = point_details.point_balance
                if loyalty_points - int(loyalty_points) == 0:
                    loyalty_points = int(loyalty_points)
                validity = point_details.points_date + timedelta(days=1095)
                current_date = date.today()
                if current_date == validity:
                    loyalty_points = 0
                    validity = current_date + timedelta(days=1095)
                    point_details.point_balance = loyalty_points
                    point_details.points_date = validity
                    point_details.save()
                # ! Enable after app gets approved
                sync_status = online_sync_points(user.email, point_details)
                if sync_status:
                    loyalty_points = int(point_details.point_balance)

                loyalty_point_worth = (
                    loyalty_points * settings.ONE_LOYALTY_POINT_WORTH_VALUE
                )
                return Response(
                    {
                        "status": "Success",
                        "data": {
                            "points_available": loyalty_points,
                            "point_validity": datetime.strftime(validity, "%d/%m/%Y"),
                            "points_worth": f"Dhs {loyalty_point_worth}",
                        },
                    }
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def put(request):
        """
        PUT method which updates a users point balance in earn scenario
        """
        try:
            invoice = request.data["data"]
            if (
                not (
                    "invoice" in invoice
                    and "Name" in invoice
                    and "Price" in invoice
                    and "quantity" in invoice
                )
                or "amountApplied" in invoice
            ):
                return Response(
                    {"status": "Failed", "message": "Invalid QR code"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            point_details = PointsDB.objects.get(user=request.user.id)
            points_available = point_details.point_balance
            product_details = invoice.split(",")
            loyalty_percentage = 0
            app_config = AppConfigDB.objects.get(id=1)
            if app_config:
                loyalty_percentage = app_config.loyalty_percent
            else:
                loyalty_percentage = settings.LOYALTY_DEFAULT_PERCENTAGE
            loyalty_point_worth = settings.ONE_LOYALTY_POINT_WORTH_VALUE
            total_product_price = 0
            product_price = 0
            invoice_id = None
            product_data = []

            for i in product_details:
                info = i.split(":")
                search_text = info[0].strip()
                search_value = info[1].strip()
                if search_text == "invoice":
                    invoice_id = search_value
                if search_text.lower() == "price":
                    cost = decimal.Decimal(search_value)
                    product_price += math.floor(cost)
                if search_text.lower() == "quantity":
                    product_price *= int(search_value)
                    total_product_price += product_price
                    product_price = 0

            loyalty_points = total_product_price * (loyalty_percentage / 100)
            new_points = points_available + decimal.Decimal(loyalty_points)
            point_details.point_balance = math.floor(new_points)
            point_details.save()

            # ! Enable after app gets approved
            online_sync_points(request.user.email, point_details)

            for j in range(0, len(product_details)):
                info = product_details[j].split(":")
                if info[0].strip().lower() == "name":
                    tran_product = {}
                    tran_product["name"] = info[1].strip()
                    quantity_info = product_details[j + 2].split(":")
                    tran_product["quantity"] = int(quantity_info[1].strip())
                    price_info = product_details[j + 1].split(":")
                    tran_product["price"] = round(
                        decimal.Decimal(price_info[1].strip()), 4
                    )
                    tran_product["points_applied"] = math.floor(
                        math.floor(round(decimal.Decimal(price_info[1].strip()), 4))
                        * tran_product["quantity"]
                        * (loyalty_percentage / 100)
                    )
                    product_data.append(tran_product)

            tran_data = {
                "invoice_id": invoice_id,
                "user": request.user.id,
            }

            for k in product_data:
                tran_data["product_name"] = str(k["name"])
                tran_data["product_cost"] = k["price"]
                # tran_data['points_applied'] = math.floor(decimal.Decimal(
                #     math.floor(k['price'])*(loyalty_percentage/100)))
                tran_data["points_applied"] = k["points_applied"]
                tran_data["points_deducted"] = 0
                tran_data["quantity"] = k["quantity"]
                tran_data["returned"] = False
                tran_serializer = TransactionSerializer(data=tran_data)
                if tran_serializer.is_valid():
                    transaction = tran_serializer.create(tran_serializer.validated_data)
                    earn_points_data = {
                        "userId": request.user.email,
                        "eventName": "Earn Points Successful",
                        "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                        "eventData": {
                            "Status": True,
                            "Points Earned": float(
                                tran_serializer.validated_data["points_applied"]
                            ),
                            "Product Name": tran_serializer.validated_data[
                                "product_name"
                            ],
                            "Product Price": float(
                                tran_serializer.validated_data["product_cost"]
                            ),
                        },
                    }
                    webengage_log_events(earn_points_data, "events")
                    log_user_points_webengage(request.user)
                    if not transaction:
                        return Response(
                            {
                                "status": "Failed",
                                "message": "Error when updating transaction details",
                            },
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        )
                else:
                    return Response(
                        tran_serializer.errors,
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )

            loyalty_point_worth = math.floor(loyalty_points * loyalty_point_worth)
            return Response(
                {
                    "status": "Success",
                    "message": "Points added to user account",
                    "points_worth": loyalty_point_worth,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class VoucherAPI(APIView):
    """
    APIView which will create a new voucher for a user based on the points they are redeeming
    for and verify the voucher code
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def get(request):
        """
        GET method which will verify the voucher code
        """
        try:
            voucher_code = request.GET["code"]
            voucher_details = VoucherCodeDB.objects.get(voucher_code=voucher_code)
            if not voucher_details.redeemed:
                return Response(
                    {
                        "status": "Failed",
                        "message": "Voucher hasn't been redeemed in store",
                    },
                    status=status.HTTP_406_NOT_ACCEPTABLE,
                )
            return Response(
                {
                    "status": "Success",
                    "message": "Voucher has been redeemed from store",
                },
                status=status.HTTP_200_OK,
            )
        except ObjectDoesNotExist as ex:
            return Response(
                {
                    "status": "Failed",
                    "message": "Voucher code entered is not in the system",
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def post(request):
        """
        POST method which will create a voucher code for a user
        """
        try:
            user = User.objects.get(id=request.user.id)
            points_redeemed = request.data["points_redeemed"]
            if points_redeemed <= 0:
                return Response(
                    {"status": "Failed", "message": "Points should be greater than 0"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            voucher_details = StoreVoucherCode(user, points_redeemed)
            if voucher_details["status"] == "Success":
                return Response(
                    {
                        "status": "Success",
                        "data": {"voucher_code": voucher_details["voucher_code"]},
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"status": "Failed", "message": voucher_details["message"]},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RedeemPointsAPI(APIView):
    """
    APIView which will create a voucher code for the user
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def put(request):
        """
        PUT method which will redeem the points from the users account and update the
        users point balance
        """

        try:
            invoice = request.data["data"]
            point_details = PointsDB.objects.get(user=request.user.id)
            points_available = point_details.point_balance
            invoice_data = invoice.split(",")
            loyalty_point_worth = settings.ONE_LOYALTY_POINT_WORTH_VALUE
            loyalty_percentage = 0
            app_config = AppConfigDB.objects.get(id=1)
            if app_config:
                loyalty_percentage = app_config.loyalty_percent
            else:
                loyalty_percentage = settings.LOYALTY_DEFAULT_PERCENTAGE
            total_product_price = 0
            total_amount_applied = 0
            product_price = 0
            invoice_id = None
            product_data = []

            if not (
                "invoice" in invoice
                and "Name" in invoice
                and "Price" in invoice
                and "quantity" in invoice
                and "amountApplied" in invoice
            ):
                return Response(
                    {"status": "Failed", "message": "Invalid QR code"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            for i in invoice_data:
                info = i.split(":")
                search_text = info[0].strip()
                search_value = info[1].strip()
                if search_text.lower() == "invoice":
                    invoice_id = search_value
                if search_text.lower() == "price":
                    cost = decimal.Decimal(search_value)
                    product_price += math.floor(cost)
                if search_text.lower() == "quantity":
                    product_price *= int(search_value)
                    total_product_price += product_price
                    product_price = 0
                if search_text == "amountApplied":
                    discount = decimal.Decimal(search_value)
                    total_amount_applied += discount

            loyalty_points = (
                total_product_price - math.floor(total_amount_applied)
            ) * (loyalty_percentage / 100)
            new_points = (points_available - total_amount_applied) + decimal.Decimal(
                loyalty_points
            )
            point_details.point_balance = math.floor(new_points)
            point_details.save()
            if (
                total_amount_applied > loyalty_points
            ):  # ! Enable after app gets approved
                online_sync_points(request.user.email, point_details, deduct=True)
            else:
                online_sync_points(request.user.email, point_details)

            for j in range(0, len(invoice_data)):
                info = invoice_data[j].split(":")
                if info[0].strip().lower() == "name":
                    tran_product = {}
                    tran_product["name"] = info[1].strip()
                    price_info = invoice_data[j + 1].split(":")
                    tran_product["price"] = round(
                        decimal.Decimal(price_info[1].strip()), 4
                    )
                    quantity_info = invoice_data[j + 2].split(":")
                    tran_product["quantity"] = int(quantity_info[1].strip())
                    discount_amount = invoice_data[j + 3].split(":")
                    discount_amount_final = round(
                        decimal.Decimal(discount_amount[1].strip()), 4
                    )
                    tran_product["discount_amount"] = discount_amount_final
                    amount_to_be_applied = (
                        math.floor(decimal.Decimal(price_info[1].strip()))
                        * tran_product["quantity"]
                    ) - discount_amount_final
                    tran_product["points_applied"] = math.floor(
                        round(
                            float(amount_to_be_applied) * (loyalty_percentage / 100), 4
                        )
                    )
                    product_data.append(tran_product)

            tran_data = {
                "invoice_id": invoice_id,
                "user": request.user.id,
            }

            for k in product_data:
                tran_data["product_name"] = k["name"]
                tran_data["product_cost"] = k["price"]
                tran_data["quantity"] = k["quantity"]
                tran_data["points_applied"] = k["points_applied"]
                tran_data["points_deducted"] = k["discount_amount"]
                tran_data["returned"] = False
                tran_serializer = TransactionSerializer(data=tran_data)
                if tran_serializer.is_valid():
                    transaction = tran_serializer.create(tran_serializer.validated_data)

                    earn_points_data = {
                        "userId": request.user.email,
                        "eventName": "Earn Points Successful",
                        "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                        "eventData": {
                            "Status": True,
                            "Points Earned": float(
                                tran_serializer.validated_data["points_applied"]
                            ),
                            "Product Name": tran_serializer.validated_data[
                                "product_name"
                            ],
                            "Product Price": float(
                                tran_serializer.validated_data["product_cost"]
                            ),
                        },
                    }
                    webengage_log_events(earn_points_data, "events")

                    redeem_points_data = {
                        "userId": request.user.email,
                        "eventName": "Voucher Redeemed Successful",
                        "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                        "eventData": {
                            "Redeem Points": float(
                                tran_serializer.validated_data["points_deducted"]
                            ),
                            "Product Name": tran_serializer.validated_data[
                                "product_name"
                            ],
                            "Product Price": float(
                                tran_serializer.validated_data["product_cost"]
                            ),
                            "Invoice ID": tran_serializer.validated_data["invoice_id"],
                        },
                    }
                    webengage_log_events(redeem_points_data, "events")

                    log_user_points_webengage(request.user)

                    if not transaction:
                        return Response(
                            {
                                "status": "Failed",
                                "message": "Error when updating transaction details",
                            },
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        )
            redeem_points_worth = math.floor(total_amount_applied * loyalty_point_worth)
            earn_points_worth = math.floor(loyalty_points * loyalty_point_worth)
            return Response(
                {
                    "status": "Success",
                    "message": "User's point balance has been updated",
                    "redeem_points_worth": redeem_points_worth,
                    "earn_points_worth": earn_points_worth,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class GetUserTransactionAPI(APIView):
    """
    APIView which will fetch the user transactions
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required("api.app_user", raise_exception=True)
    def get(request):
        """
        GET Method which will fetch the user's transaction details
        """
        try:
            user = User.objects.get(id=request.user.id)
            transactions = TransactionDB.objects.filter(user=user).order_by(
                "-transaction_date"
            )
            user_tran_data = []
            for i in transactions:
                temp_tran_data = {}
                temp_tran_data["product_name"] = i.product_name
                temp_tran_data["product_cost"] = i.product_cost
                tran_date = i.transaction_date.date()
                temp_tran_data["transaction_date"] = datetime.strftime(
                    tran_date, "%d/%m/%Y"
                )
                if i.points_applied > 0:
                    temp_tran_data["points"] = abs(i.points_applied)
                    user_tran_data.append(temp_tran_data)
                if i.points_deducted > 0:
                    new_temp_tran_data = temp_tran_data.copy()
                    new_temp_tran_data["points"] = -abs(i.points_deducted)
                    user_tran_data.append(new_temp_tran_data)
            return Response(
                {"status": "Success", "data": user_tran_data}, status=status.HTTP_200_OK
            )

        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class DeleteUserAPI(APIView):
    """
    APIView which will delete a user's account from the rewards app system
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    def delete(request):
        """
        Method which will delete the user's account from the rewards app system
        """
        try:
            user_id = request.user.id
            request.user.auth_token.delete()
            logout(request)
            user = User.objects.get(id=user_id)
            user_email = user.email
            user.delete()
            delete_account_data = {
                "userId": user_email,
                "eventName": "Delete An Account",
                "eventTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0400"),
                "eventData": {},
            }
            webengage_log_events(delete_account_data, "events")
            return Response(
                {
                    "status": "Success",
                    "message": "User account has been deleted from the system",
                },
                status=status.HTTP_200_OK,
            )
        except ObjectDoesNotExist:
            return Response(
                {"status": "Failed", "message": "Incorrect email address or password"},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class SonyWorldAPI(APIView):
    """
    APIView which will pass data to Sony World portal
    """
    def post(request):
        """
        POST Method which will pass data to sony world portal
        """
        email = request.data["email"]

        try:
            user = User.objects.get(email=email)
            points_data = PointsDB.objects.get(user=user)
            points = int(points_data.point_balance)
            return Response({
                "is_member": True,
                "points_available": points,
                "critical_alert": None

            }, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({
                "is_member": False,
                "points_available": None,
                "critical_alert": None
            }, status=status.HTTP_200_OK)


class SSOLoginView(APIView):
    """
    APIView which will authenticate a user using SSO
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def get(request):
        """
        GET method which will authenticate a user using SSO
        """
        try:
            email = request.query_params.get("email")
            if not email:
                user = request.user
                code = request.query_params.get("code")
                data = {
                    "code": code,
                    "client_id": getattr(settings, "MDCIM_CLIENT_ID"),
                    "client_secret": getattr(settings, "MDCIM_CLIENT_SECRET"),
                    "grant_type": "authorization_code",
                    "scope": "[openid|users]",
                    "redirect_uri": getattr(settings, "MDCIM_REDIRECT_URL")
                }

                response = requests.post(
                    f"{getattr(settings, 'SSO_URL')}/v2/oauth2/token", data=data
                ).json()

                if "error" in response:
                    return Response(
                        {"status": "Failed", "message": response["message"]},
                        status=status.HTTP_401_UNAUTHORIZED,
                    )
                res = requests.get(
                    f"{getattr(settings, 'SSO_URL')}/v2/users/me",
                    headers={"Authorization": "Bearer " + response["access_token"]},
                ).json()

                try:
                    user = User.objects.get(email=res['email'])
                except User.DoesNotExist:
                    user = User.objects.create_user(
                        username=res['email'],
                        email=res['email'],
                        first_name=res['first_name'],
                        last_name=res['last_name'],
                        password=res['guid'],
                    )
                    permission = Permission.objects.get(name="App user permissions")
                    user.user_permissions.add(permission)
                    user.save()
                    PointsDB.objects.create(user=user)
                    UserDB.objects.create(
                        user=user,
                        user_type="app",
                        country=res['legal_country'],
                    )

                user_db = UserDB.objects.get(user=user)
                user_db.refresh_token = response["refresh_token"]
                user_db.guid = res['guid']
                user_db.save()
                authenticate(request, username=res['email'], password=res['guid'])
            else:
                user = User.objects.get(email=email)
                user_db = UserDB.objects.get(user=user)
            
            login(request, user, "api.backends.EmailAuthBackend")

            try:
                token = Token.objects.get(user=user)
            except Token.DoesNotExist:
                token = Token.objects.create(user=user)
            

            channel_layer = get_channel_layer()
            group_name = re.sub(r'[^a-zA-Z0-9.-]', '-', user.email)
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    'type': 'task_data',
                    'data':
                    {
                        "status": "Success",
                        "message": "User logged in successfully",
                        "data": {
                            "user_id": user.id,
                            "username": user.username,
                            "first_name": user.first_name,
                            "last_name": user.last_name,
                            "email": user.email,
                            "token": token.key,
                            "user_type": user_db.user_type,
                            "country": user_db.country,
                            "mdcim_popup": False,
                            "mdcim_user": True if user_db.guid else False
                        },
                    }
                }
            )

            if user.is_authenticated:
                return Response(
                    {
                        "status": "Success",
                        "message": "User is logged in to the system",
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {
                        "status": "Failed", "message": "User is not logged in",
                        "data": response
                     },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ProfileTransferAPI(APIView):
    """
    APIView which will transfer the profile of a user from MDCIM to the loyalty app
    """

    permission_classes = (permissions.AllowAny,)

    @staticmethod
    def post(request):
        """
        POST method which will transfer the profile of a user from MDCIM to the loyalty app
        """
        try:
            email = request.data["email"]
            user = User.objects.get(email=email)
            user_db = UserDB.objects.get(user=user)
            user_db.save()

            data = {
                "email": user.email,
                "legal_country": user_db.country.upper(),
                "language": "en-AE",
                "first_name": user.first_name,
                "last_name": user.last_name,
            }

            response = requests.post(
                f"https://multi-transfer.acm.account.sony.com/v1/{getattr(settings, 'MDCIM_CLIENT_ID')}/profiles",
                headers={"X-Api-Key": getattr(settings, "MDCIM_API_KEY")},
                data=data
            ).json()

            print(response, "response of profile transfer api.")
            try:
                if response['profile_id']:
                    return Response(
                        {
                            "status": "Success",
                            "message": "User profile transferred successfully",
                            "data": response
                        },
                        status=status.HTTP_200_OK,
                    )
            except KeyError:
                return Response(
                    {
                        "status": "Failed",
                        "message": "User profile transfer failed",
                        "data": response
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except ObjectDoesNotExist:
            return Response(
                {"status": "Failed", "message": "User does not exist in system"},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
