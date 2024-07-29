# import time
import math
import random
from datetime import datetime
from typing import Dict

import requests
from django import utils
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.core.cache.backends.base import DEFAULT_TIMEOUT
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Sum
from django.utils.crypto import get_random_string

from .models import PointsDB, TransactionDB, UserDB, VoucherCodeDB

CACHE_TTL = getattr(settings, "CACHE_TTL", DEFAULT_TIMEOUT)


def GenerateOtp() -> str:
    """
    Function which will create a unique otp
    """
    digits = "0123456789"
    otp = ""
    for i in range(4):
        otp += digits[math.floor(random.random() * 10)]
    return otp


def RetrieveOTP(email: str, otp_type: str) -> dict:
    """
    Function which will generate and store the OTP to be sent to a user
    """
    try:
        if otp_type == "forget-password":
            user = User.objects.get(email=email)
            user_details = UserDB.objects.get(user=user)
            if user_details.user_type == "alpha":
                return {
                    "status": "Failed",
                    "message": "Please change password from Alpha Universe Website",
                }
            otp = ""
            while True:
                otp = GenerateOtp()
                otp_details = {"user": user, "verified": False}
                result = cache.add(otp, otp_details, CACHE_TTL)
                if result:
                    break
            return {
                "status": "Success",
                "data": {"first_name": user.first_name, "otp": otp},
            }
        else:
            if User.objects.filter(email=email).exists():
                return {"status": "Failed", "message": "User account already exists"}
            else:
                otp = ""
                while True:
                    otp = GenerateOtp()
                    otp_details = {"user": None, "verified": False}
                    result = cache.add(otp, otp_details, CACHE_TTL)
                    if result:
                        break
                return {"status": "Success", "data": {"first_name": "User", "otp": otp}}
    except ObjectDoesNotExist:
        return {"status": "Failed", "message": "User account doesn't exist"}
    except Exception as e:
        return {"status": "Failed", "message": e.args}


def VerifyOtp(otp: str, otp_type: str) -> dict:
    """
    Comment
    """
    try:
        if otp in cache:
            user_otp = cache.get(otp)
            user_email = ""
            if otp_type == "forget-password":
                user_email = user_otp["user"].email
            user_otp["verified"] = True
            cache.delete(otp)
            return {"status": "Success", "data": {"email": user_email}}
        else:
            return {"status": "Failed", "message": "Unable to verify the OTP"}
    except ObjectDoesNotExist:
        return {"status": "Failed", "message": "OTP entered is incorrect"}
    except Exception as e:
        return {"status": "Failed", "message": e.args}


def StoreVoucherCode(user: User, redeemed_points: int):
    """
    Store Voucher code for a user in DB
    """
    try:
        user_points = PointsDB.objects.get(user=user)
        if redeemed_points > user_points.point_balance:
            return {"status": "Failed", "message": "User doesn't have enough points"}
        VoucherCodeDB.objects.filter(user=user).delete()
        voucher_code = get_random_string(
            length=10, allowed_chars=("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        )
        store_voucher = VoucherCodeDB.objects.create(
            user=user,
            voucher_code=voucher_code,
            voucher_value=redeemed_points,
            redeemed=False,
        )
        if store_voucher:
            return {"status": "Success", "voucher_code": voucher_code}
        else:
            return {
                "status": "Failed",
                "message": "Error when trying to create voucher code",
            }
    except Exception as e:
        return {"status": "Failed", "message": e.args}


def user_identifier(email: str) -> dict:
    """
    Creating token for a user to verify that they are changing the password
    """
    try:
        user = User.objects.get(email=email)
        b64_id = utils.http.urlsafe_base64_encode(utils.encoding.force_bytes(user.id))
        token = default_token_generator.make_token(user)
        return {"status": "Success", "data": {"token": token, "uidb64": b64_id}}
    except ObjectDoesNotExist:
        return {"status": "Failed", "message": "User account doesn't exist"}
    except Exception as e:
        return {"status": "Failed", "message": e.args}


def AlphaLogin(email: str, password: str) -> dict:
    """
    Function which will check if a user is registered with Alpha Universe
    """
    url = "https://alphauniverse-mea.com/wp-json/alpha-loyality-plugin/login"
    data = {"username": email, "password": password}
    response = requests.post(url=url, data=data)
    return response.json()


def online_auth():
    """
    Function which will authenticate with Sony online system
    """
    online_api = getattr(settings, "GROWAVE_DETAILS").get("get_url")
    data = {
        "client_id": (None, getattr(settings, "GROWAVE_DETAILS").get("client_id")),
        "client_secret": (
            None,
            getattr(settings, "GROWAVE_DETAILS").get("client_secret"),
        ),
        "scope": (None, "read_user write_user read_reward write_reward"),
        "grant_type": (None, "client_credentials"),
    }
    url = f"{online_api}/access_token"
    response = requests.post(url=url, files=data)
    if response.status_code == 200:
        data = response.json()
        return data["access_token"]
    else:
        return None


def online_user_fetch(email: str):
    """
    Function which will fetch user points from Sony Online website
    """
    access_token = online_auth()
    online_api = getattr(settings, "GROWAVE_DETAILS").get("get_url")
    url = f"{online_api}/users/search?email={email}"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        user_data = {"email": data["data"]["email"], "points": data["data"]["points"]}
    else:
        user_data = {}
    return user_data


def online_points_update(update_data: Dict):
    """
    Function which will update the points in sony online website
    """
    access_token = online_auth()
    online_api = getattr(settings, "GROWAVE_DETAILS").get("post_url")
    url = f"{online_api}/reward/editPointsBalance"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    response = requests.post(url, headers=headers, json=update_data)
    if response.status_code == 200:
        data = response.json()
        if data["message"] == "Success" and data["status"] == 200:
            return True
    else:
        return False


def online_user_activities(user_email: str):
    """
    Function which will fetch user's activity in sony online website
    """
    access_token = online_auth()
    online_api = getattr(settings, "GROWAVE_DETAILS").get("get_url")
    url = f"{online_api}/reward/users-activities?email={user_email}&order=desc"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data["status"] == 200:
            return data["data"]
    else:
        return []


def online_sync_points(user_email: str, point_details: PointsDB, deduct: bool = False):
    """
    Function which will compare online points with loyalty app points
    and sync them if they are not the same
    """
    user_online_points = online_user_fetch(user_email).get("points")
    if user_online_points != None:
        user_online_points = int(user_online_points)
        loyalty_points = point_details.point_balance
        if user_online_points > loyalty_points:
            point_diff = user_online_points - loyalty_points
            if deduct:
                online_points_update(
                    {
                        "email": user_email,
                        "points": f"-{point_diff}",
                        "comment": "Points Sync with Rewards App",
                    }
                )
            else:
                loyalty_points += point_diff
                point_details.point_balance = loyalty_points
                point_details.save()
        else:
            point_diff = loyalty_points - user_online_points
            user_hist = online_user_activities(user_email)
            if user_hist:
                redeem_hist = [
                    {"redeem_points": hist["spend"], "time": hist["creation_time"]}
                    for hist in user_hist
                    if hist["type"] == "redeem"
                ]
                if redeem_hist:
                    latest_redeem_hist_time = datetime.utcfromtimestamp(
                        redeem_hist[0]["time"]
                    )
                    latest_points_update = point_details.last_update.replace(
                        tzinfo=None
                    )
                    if latest_redeem_hist_time < latest_points_update:
                        online_points_update(
                            {
                                "email": user_email,
                                "points": f"+{point_diff}",
                                "comment": "Points Sync with Rewards App",
                            }
                        )
                    else:
                        point_details.point_balance = loyalty_points - point_diff
                        point_details.save()
                else:
                    online_points_update(
                        {
                            "email": user_email,
                            "points": f"+{point_diff}",
                            "comment": "Points Sync with Rewards App",
                        }
                    )
            else:
                online_points_update(
                    {
                        "email": user_email,
                        "points": f"+{point_diff}",
                        "comment": "Points Sync with Rewards App",
                    }
                )
        return True
    else:
        return False


def webengage_log_events(event_data, type):
    """
    Function which will log events unique to users of rewards app
    """

    webengage_data = getattr(settings, "WEBENGAGE_DETAILS")
    base_webengage_url = (
        f'{webengage_data.get("url")}/{webengage_data.get("license_code")}'
    )
    final_webengage_url = (
        f"{base_webengage_url}/events"
        if type == "events"
        else f"{base_webengage_url}/users"
    )
    api_token = webengage_data.get("api_key")
    headers = {"Authorization": f"Bearer {api_token}"}
    log_resp = requests.post(final_webengage_url, headers=headers, json=event_data)
    if log_resp.status_code == 201:
        data = log_resp.json()
        if data.get("response").get("status") == "queued":
            return True
        else:
            return False
    else:
        return False


def log_user_points_webengage(user):
    """
    Function which will update user profile on every transaction done
    by a user in webengage log system
    """

    transactions = TransactionDB.objects.filter(user__email=user.email)
    earned_points = transactions.aggregate(Sum("points_applied")).get(
        "points_applied__sum", 0
    )
    redeem_points = transactions.aggregate(Sum("points_deducted")).get(
        "points_deducted__sum", 0
    )
    point_balance = (
        PointsDB.objects.values("point_balance")
        .get(user__email=user.email)
        .get("point_balance", 0)
    )
    user_consent = (
        UserDB.objects.values("promotion_consent")
        .get(user__email=user.email)
        .get("promotion_consent", False)
    )
    user_data = {
        "userId": user.email,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "email": user.email,
        "attributes": {
            "Total No.of Transactions": transactions.count(),
            "Total No.of Earned Points": float(earned_points) if earned_points else 0,
            "Total No.of Redeemed points": float(redeem_points) if redeem_points else 0,
            "Rewards Balance": float(point_balance) if point_balance else 0,
            "Subscribed to news letter": user_consent if user_consent else False,
        },
    }
    webengage_log_events(user_data, "user")
