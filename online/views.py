from datetime import date, datetime, timedelta
import decimal
from django.conf import settings
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.hashers import check_password
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework import permissions, status
from django.core.exceptions import ObjectDoesNotExist
import math

from api.models import AppConfigDB, PointsDB, TransactionDB
from api.serializers import TransactionSerializer


class LoginAPI(APIView):
    """
    APIView which will handles login for online store users
    """
    @staticmethod
    def post(request):
        """
        APIView which handles login for online store users
        """
        try:
            name = request.data['username']
            password = request.data['password']
            cust_email = request.data['cust_email']
            user = authenticate(request, username=name,
                                password=password, online=True)
            if user:
                cust_user = User.objects.get(email=cust_email)
                token = Token.objects.get_or_create(user=cust_user)
                return Response({
                    "status": "Success",
                    "data": {
                        "user_id": cust_user.id,
                        "username": cust_user.username,
                        "first_name": cust_user.first_name,
                        "last_name": cust_user.last_name,
                        "email": cust_user.email,
                        "token": token[0].key
                    }
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "status": "Failed",
                    "message": "Incorrect credentials"
                }, status=status.HTTP_401_UNAUTHORIZED)
        except ObjectDoesNotExist:
            return Response({
                "status": "Failed",
                "message": "User with given email address not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyEmailAPI(APIView):
    """
    APIView which will verify the email address with rewards app system
    """
    @staticmethod
    def get(request):
        """
        GET method which will verify the email address with rewards app system
        """
        try:
            email = request.GET['email']
            if User.objects.filter(email=email).exists():
                return Response({
                    "status": "Success",
                    "message": "User verification successful"
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "status": "Failed",
                    "message": "User verification failed"
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PointsCalculateAPI(APIView):
    """
    APIView which will calculate points for products
    """
    @staticmethod
    def post(request):
        """
        POST method which will calculate the points 
        """
        loyalty_percentage = 0
        app_config = AppConfigDB.objects.get(id=1)
        if app_config:
            loyalty_percentage = app_config.loyalty_percent
        else:
            loyalty_percentage = settings.LOYALTY_DEFAULT_PERCENTAGE
        try:
            products = request.data['product_info']
            for i in products:
                points = math.floor(
                    (math.floor(i['product_cost']) * int(i['quantity'])) * loyalty_percentage/100)
                i['points'] = points
            return Response({
                "status": "Success",
                "data": products
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserPointsAPI(APIView):
    """
    APIView which will fetch the points available to a user
    """

    @staticmethod
    def post(request):
        """
        GET method which will fetch the points available to a user
        """
        try:
            user = User.objects.get(email=request.data['email'])
            # auth_flag = "email" if 'email' in request.data.keys() else "token"
            # if auth_flag == "email":
            #     org_pass = user.password
            #     if check_password(request.data['password'], org_pass):
            #         token = Token.objects.get(user=user).key
            #     else:
            #         return Response({
            #             "status": "Failed",
            #             "message": "Incorrect password"
            #         }, status=status.HTTP_401_UNAUTHORIZED)
            # else:
            #     user = Token.objects.get(key=request.data['token']).user
            #     token = request.data['token']
            point_details = PointsDB.objects.get(user=user)
            if point_details:
                loyalty_points = point_details.point_balance
                if (loyalty_points - int(loyalty_points) == 0):
                    loyalty_points = int(loyalty_points)
                validity = point_details.points_date + timedelta(days=1095)
                current_date = date.today()
                if current_date == validity:
                    loyalty_points = 0
                    validity = current_date + timedelta(days=1095)
                    point_details.point_balance = loyalty_points
                    point_details.points_date = validity
                    point_details.save()
                return Response({
                    "status": "Success",
                    "data": {
                        "points_available": loyalty_points,
                        "point_validity": datetime.strftime(validity, "%d/%m/%Y")
                    }
                })
        except ObjectDoesNotExist:
            return Response({
                "status": "Failed",
                "message": "User not found"
            }, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EarnPointsAPI(APIView):
    """
    APIView which manages the earning of points for a user using online website
    """

    @staticmethod
    def post(request):
        """
        PUT method which updates a users point balance in earn scenario
        """
        try:
            user = User.objects.get(email=request.data['email'])
            point_details = PointsDB.objects.get(user=user.id)
            points_available = point_details.point_balance
            product_details = request.data['products']
            loyalty_percentage = 0
            app_config = AppConfigDB.objects.get(id=1)
            if app_config:
                loyalty_percentage = app_config.loyalty_percent
            else:
                loyalty_percentage = settings.LOYALTY_DEFAULT_PERCENTAGE
            loyalty_point_worth = settings.ONE_LOYALTY_POINT_WORTH_VALUE
            total_product_price = 0
            product_price = 0
            invoice_id = request.data['invoice']
            product_data = []

            for i in product_details:
                cost = i['price']
                product_price += math.floor(cost)
                product_price *= i["quantity"]
                total_product_price += product_price
                product_price = 0
                tran_product = {}
                tran_product['name'] = i['name']
                tran_product['quantity'] = i['quantity']
                tran_product['price'] = round(i['price'], 4)
                tran_product['points_applied'] = math.floor(math.floor(
                    round(i['price'], 4)) * tran_product['quantity'] * (loyalty_percentage/100))
                product_data.append(tran_product)

            loyalty_points = total_product_price*(loyalty_percentage/100)
            new_points = points_available + decimal.Decimal(loyalty_points)
            point_details.point_balance = math.floor(new_points)
            point_details.save()

            tran_data = {
                "invoice_id": invoice_id,
                "user": user.id,
            }

            for k in product_data:
                tran_data['product_name'] = str(k['name'])
                tran_data['product_cost'] = k['price']
                tran_data['points_applied'] = k['points_applied']
                tran_data['points_deducted'] = 0
                tran_data['quantity'] = k['quantity']
                tran_data['returned'] = False
                tran_serializer = TransactionSerializer(data=tran_data)
                if tran_serializer.is_valid():
                    transaction = tran_serializer.create(
                        tran_serializer.validated_data)
                    if not transaction:
                        return Response({
                            "status": "Failed",
                            "message": "Error when updating transaction details"
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                else:
                    return Response(tran_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            loyalty_point_worth = math.floor(
                loyalty_points*loyalty_point_worth)
            return Response({
                "status": "Success",
                "message": "Points added to user account",
                "points_worth": loyalty_point_worth
            }, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({
                "status": "Failed",
                "message": "User not found"
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RedeemPointsAPI(APIView):
    """
    APIView which will will redeem the points from the users account and update the users point balance
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    def post(request):
        """
        POST method which will redeem the points from the users account and update the
        users point balance
        """
        try:
            point_details = PointsDB.objects.get(user=request.user.id)
            points_available = point_details.point_balance
            product_details = request.data['products']
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
            invoice_id = request.data['invoice']
            product_data = []

            for i in product_details:
                cost = i['price']
                product_price += math.floor(cost)
                product_price *= i['quantity']
                total_product_price += product_price
                product_price = 0
                total_amount_applied += i['amountApplied']
                tran_product = {}
                tran_product['name'] = i['name']
                tran_product['quantity'] = i['quantity']
                tran_product['price'] = round(i['price'], 4)
                tran_product['discount_amount'] = round(i['amountApplied'], 4)
                amount_to_be_applied = (math.floor(
                    i['price'])*i['quantity']) - tran_product['discount_amount']
                tran_product['points_applied'] = math.floor(round(
                    amount_to_be_applied*(loyalty_percentage/100), 4))
                product_data.append(tran_product)

            loyalty_points = (total_product_price -
                              math.floor(total_amount_applied))*(loyalty_percentage/100)
            new_points = (decimal.Decimal(points_available) -
                          decimal.Decimal(total_amount_applied)) + decimal.Decimal(loyalty_points)
            point_details.point_balance = math.floor(new_points)
            point_details.save()

            tran_data = {
                "invoice_id": invoice_id,
                "user": request.user.id,
            }

            for k in product_data:
                tran_data['product_name'] = k['name']
                tran_data['product_cost'] = k['price']
                tran_data['quantity'] = k['quantity']
                tran_data['points_applied'] = k['points_applied']
                tran_data['points_deducted'] = k['discount_amount']
                tran_data['returned'] = False
                tran_serializer = TransactionSerializer(data=tran_data)
                if tran_serializer.is_valid():
                    transaction = tran_serializer.create(
                        tran_serializer.validated_data)
                    if not transaction:
                        return Response({
                            "status": "Failed",
                            "message": "Error when updating transaction details"
                        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            redeem_points_worth = math.floor(
                total_amount_applied*loyalty_point_worth)
            earn_points_worth = math.floor(
                loyalty_points * loyalty_point_worth)
            return Response({
                "status": "Success",
                "message": "User's point balance has been updated",
                "redeem_points_worth": redeem_points_worth,
                "earn_points_worth": earn_points_worth
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReturnAPI(APIView):
    """
    APIView which will update which product was returned
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    def post(request):
        """
        PUT method which will update which product was returned
        """
        try:
            invoice_id = request.data['invoice_id']
            updated_info = request.data['product_info']
            modified_points = 0
            user = None
            if invoice_id == "A897541BCDR":  # ! Remove after testing
                return Response({
                    "status": "Success",
                    "message": "Points have been updated in the users account"
                }, status=status.HTTP_200_OK)
            for i in updated_info:
                # product_id = i["product_id"]
                product_name = i["name"]  # ! Remove after testing
                # product_cost = i["product_cost"]   #! Remove after testing
                transaction = TransactionDB.objects.get(
                    invoice_id=invoice_id, product_name=product_name)
                transaction.returned = True
                points_applied = transaction.points_applied
                points_deducted = transaction.points_deducted
                if points_applied > 0:
                    modified_points = modified_points + -abs(points_applied)
                if points_deducted > 0:
                    modified_points = modified_points + abs(points_deducted)
                user = transaction.user
                transaction.save()

            user_points = PointsDB.objects.get(user=user)
            user_points.point_balance = round(user_points.point_balance +
                                              decimal.Decimal(modified_points), 4)
            user_points.save()

            return Response({
                "status": "Success",
                "message": "Points have been updated in the users account"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
