from datetime import datetime
from cms.helpers import send_notification
from api.models import AppConfigDB, PointsDB, TransactionDB, UserDB
import os
from django.contrib.auth.decorators import permission_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from .serializers import FaqSerializer, OfferCategorySerializer, OfferSerializer, ProductSerializer
from django.core import serializers
from django.db import OperationalError
from .models import FaqDB, OfferCategoryDB, ProductDB, OffersDB
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from django.utils.timezone import make_aware
import json


class ProductAPI(APIView):
    """
    APIView to store product information to database
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def post(request):
        """
        POST method which will create a new product
        """
        try:
            product_serializer = ProductSerializer(data=request.data)
            if product_serializer.is_valid():
                product = product_serializer.save()
                if product:
                    return Response({
                        "status": "Success",
                        "message": "Product info added successfully"
                    }, status=status.HTTP_201_CREATED)
            return Response(product_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except OperationalError as ex:
            return Response({
                "status": "Failed",
                "message": f"Error when writing to DB. {ex.args[1]}",
                "error_log": ex.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def put(request):
        """
        PUT method which will update the products information
        """
        try:
            product_id = request.data['id']
            update_product = request.data.copy()
            update_product.pop('id')
            product_info = ProductDB.objects.get(id=product_id)
            product_serializer = ProductSerializer(
                instance=product_info, data=update_product, partial=True)
            if product_serializer.is_valid():
                product = product_serializer.save()
                if product:
                    return Response({
                        "status": "Success",
                        "message": "Product info has been updated"
                    }, status=status.HTTP_200_OK)
            return Response(product_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "The product does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET method which will get the product info
        """
        try:
            product_info = serializers.serialize(
                'json', ProductDB.objects.all())
            data = json.loads(product_info)
            product_fields = []
            for i in data:
                temp_data = {}
                temp_data['id'] = i['pk']
                temp_data['product_info'] = i['fields']
                if i['fields']['image']:
                    image_link = settings.MEDIA_URL + i['fields']['image']
                    temp_data['product_info']['image'] = image_link
                product_fields.append(temp_data)
            return Response({
                "status": "Success",
                "data": product_fields
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def delete(request):
        """
        DELETE Method which will delete a product from the cms
        """
        try:
            product_id = request.data['id']
            product = ProductDB.objects.get(id=product_id)
            product.delete()
            return Response({
                "status": "Success",
                "message": "Product has been deleted"
            }, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "The product does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class OffersCategoryAPI(APIView):
    """
    APIView which will modify the offers category in db
    """
    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET Method which will fetch the category list from db
        """
        try:
            category_info = serializers.serialize(
                'json', OfferCategoryDB.objects.all())
            data = json.loads(category_info)
            category_fields = []
            for i in data:
                temp_data = {}
                temp_data['id'] = i['pk']
                temp_data['category_details'] = i['fields']
                if i['fields']['icon']:
                    icon_link = settings.MEDIA_URL + i['fields']['icon']
                    temp_data['category_details']['icon'] = icon_link
                category_fields.append(temp_data)
            return Response({
                "status": "Success",
                "data": category_fields
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def post(request):
        """
        POST Method which will create a new category in the db
        """
        try:
            offer_category_serialzier = OfferCategorySerializer(
                data=request.data)
            if offer_category_serialzier.is_valid():
                category = offer_category_serialzier.save()
                if category:
                    return Response({
                        "status": "Success",
                        "message": "Offer Category info added successfully"
                    }, status=status.HTTP_201_CREATED)
            return Response(offer_category_serialzier.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except OperationalError as ex:
            return Response({
                "status": "Failed",
                "message": f"Error when writing to DB. {ex.args[1]}",
                "error_log": ex.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def put(request):
        """
        PUT Method which will update an existing category in the db
        """
        try:
            category_id = request.data['id']
            category = OfferCategoryDB.objects.get(id=category_id)
            update_category = request.data.copy()
            update_category.pop('id')
            offer_category_serializer = OfferCategorySerializer(
                instance=category, data=update_category, partial=True)
            if offer_category_serializer.is_valid():
                category = offer_category_serializer.save()
                if category:
                    return Response({
                        "status": "Success",
                        "message": "Offer Category info has been updated"
                    }, status=status.HTTP_200_OK)
            return Response(offer_category_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "The offer category does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def delete(request):
        """
        DELETE Method which will delete a category from the db
        """
        try:
            category_id = request.data['id']
            category = OfferCategoryDB.objects.get(id=category_id)
            category.delete()
            return Response({
                "status": "Success",
                "message": "Offer Category has been deleted"
            }, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "The offer category does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class OffersAPI(APIView):

    """
    APIView which will fetch/update/delete any offers in the CMS for Sony Loyalty App
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET method which will fetch offer details from DB and display it on the cms for the sony loyalty app
        """
        try:
            offers_info = serializers.serialize(
                'json', OffersDB.objects.all())
            data = json.loads(offers_info)
            offer_fields = []
            for i in data:
                temp_data = {}
                temp_data['id'] = i['pk']
                temp_data['offer_info'] = i['fields']
                category_id = i['fields']['category']
                category_name = OfferCategoryDB.objects.get(
                    id=category_id).category_name
                temp_data['offer_info']['category'] = {
                    "id": category_id,
                    "name": category_name
                }
                if i['fields']['image_1']:
                    image_link = settings.MEDIA_URL + i['fields']['image_1']
                    temp_data['offer_info']['image_1'] = image_link
                if i['fields']['image_2']:
                    image_link = settings.MEDIA_URL + i['fields']['image_2']
                    temp_data['offer_info']['image_2'] = image_link
                if i['fields']['image_3']:
                    image_link = settings.MEDIA_URL + i['fields']['image_3']
                    temp_data['offer_info']['image_3'] = image_link
                offer_fields.append(temp_data)
            return Response({
                "status": "Success",
                "data": offer_fields
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def post(request):
        """
        POST method which will create a new offer in the db with offer details
        """
        try:
            offer_serializer = OfferSerializer(data=request.data)
            if offer_serializer.is_valid():
                offer = offer_serializer.save()
                if offer:
                    return Response({
                        "status": "Success",
                        "message": "Offer info added successfully"
                    }, status=status.HTTP_201_CREATED)
            return Response(offer_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except OperationalError as ex:
            return Response({
                "status": "Failed",
                "message": f"Error when writing to DB. {ex.args[1]}",
                "error_log": ex.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def put(request):
        """
        PUT method which update an existing offer details for an offer
        """
        try:
            offer_id = request.data['id']
            update_offer = request.data.copy()
            update_offer.pop('id')
            offer_info = OffersDB.objects.get(id=offer_id)
            offer_serializer = OfferSerializer(
                instance=offer_info, data=update_offer, partial=True)
            if offer_serializer.is_valid():
                offer = offer_serializer.save()
                if offer:
                    return Response({
                        "status": "Success",
                        "message": "Offer info has been updated"
                    }, status=status.HTTP_200_OK)
            return Response(offer_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "The offer does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def delete(request):
        """
        DELETE method which will delete the offer info from the offers db
        """
        try:
            offer_id = request.data['id']
            offer = OffersDB.objects.get(id=offer_id)
            offer.delete()
            return Response({
                "status": "Success",
                "message": "Offer has been deleted"
            }, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "The offer does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class FaqAPI(APIView):
    """
    APIView which will fetch/update/delete FAQ questions from db
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET Method which will fetch all of the faq's in the db
        """
        try:
            faq_info = serializers.serialize(
                'json', FaqDB.objects.all())
            data = json.loads(faq_info)
            faq_fields = []
            for i in data:
                temp_data = {}
                temp_data['id'] = i['pk']
                temp_data['faq_details'] = i['fields']
                faq_fields.append(temp_data)
            return Response({
                "status": "Success",
                "data": faq_fields
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def post(request):
        """
        POST method which will add a new faq to the db
        """
        try:
            faq_serializer = FaqSerializer(data=request.data)
            if faq_serializer.is_valid():
                faq = faq_serializer.save()
                if faq:
                    return Response({
                        "status": "Success",
                        "message": "FAQ added successfully"
                    }, status=status.HTTP_201_CREATED)
            return Response(faq_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except OperationalError as ex:
            return Response({
                "status": "Failed",
                "message": f"Error when writing to DB. {ex.args[1]}",
                "error_log": ex.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def put(request):
        """
        PUT Method which will update any of the faq's in the db
        """
        try:
            faq_id = request.data['id']
            faq = FaqDB.objects.get(id=faq_id)
            update_data = request.data.copy()
            update_data.pop('id')
            faq_serializer = FaqSerializer(
                instance=faq, data=update_data, partial=True)
            if faq_serializer.is_valid():
                update_faq = faq_serializer.save()
                if update_faq:
                    return Response({
                        "status": "Success",
                        "message": "FAQ has been updated"
                    }, status=status.HTTP_200_OK)
            return Response(faq_serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "The FAQ does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def delete(request):
        """
        DELETE Method which will delete the faq from db
        """
        try:
            faq_id = request.data['id']
            faq = FaqDB.objects.get(id=faq_id)
            faq.delete()
            return Response({
                "status": "Success",
                "message": "FAQ has been deleted"
            }, status=status.HTTP_200_OK)
        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "The FAQ does not exist"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UsersAPI(APIView):
    """
    APIView which will display a list of all the users using the loyalty app
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET Method which will fetch the users registered with loyalty app and display it on cms
        """
        try:
            user_info = serializers.serialize(
                'json', UserDB.objects.all())
            data = json.loads(user_info)
            user_fields = []
            for i in data:
                temp_data = {}
                if i['fields']['user_type'] == "app" or i['fields']['user_type'] == "google" or i['fields']['user_type'] == "facebook":
                    temp_data['id'] = i['pk']
                    temp_data['user_details'] = i['fields']
                    user = User.objects.get(id=i['fields']['user'])
                    user_points = PointsDB.objects.get(user=user)
                    temp_data['user_details']['username'] = user.username
                    temp_data['user_details']['first_name'] = user.first_name
                    temp_data['user_details']['last_name'] = user.last_name
                    temp_data['user_details']['email'] = user.email
                    temp_data['user_details']['point_balance'] = user_points.point_balance
                    if i['fields']['user_type'] == "alpha":
                        temp_data['user_details']['login_type'] = "alpha"
                    else:
                        temp_data['user_details']['login_type'] = temp_data['user_details']['user_type']
                    del temp_data['user_details']['fcm_token']
                    del temp_data['user_details']['user']
                    del temp_data['user_details']['user_type']
                    user_fields.append(temp_data)
            return Response({
                "status": "Success",
                "data": user_fields
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SendNotificationAPI(APIView):
    """
    APIView which will send push notification to loyalty app users phone
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def post(request):
        """
        POST Method which will send push notifications to loyalty app users
        """
        try:
            target_group = request.data['target_group'].lower()
            title = request.data['title']
            body = request.data['message']
            fcm_tokens = []
            send_status = None
            if target_group == "selected":
                user_ids = request.data['user_ids']
                for i in user_ids:
                    user_details = UserDB.objects.get(id=i)
                    fcm_tokens.append(user_details.fcm_token)
            if fcm_tokens:
                send_status = send_notification(
                    title, body, user_fcms=fcm_tokens, send_type=target_group)
            else:
                send_status = send_notification(
                    title, body, send_type=target_group)

            if send_status['status'] == "Success":
                return Response(send_status, status=status.HTTP_200_OK)
            else:
                return Response(send_status, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except ObjectDoesNotExist as ex:
            return Response({
                "status": "Failed",
                "message": "User ID not found"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TransactionAPI(APIView):
    """
    APIView which will fetch and return the transaction details to the CMS
    """
    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET method which will fetch the data from DB and show the db
        """
        try:
            transaction_data = serializers.serialize(
                'json', TransactionDB.objects.all())
            data = json.loads(transaction_data)
            transaction_fields = []
            for i in data:
                temp_data = {}
                temp_data['id'] = i['pk']
                temp_data['transaction_info'] = i['fields']
                user_details = User.objects.get(id=i['fields']['user'])
                temp_data['transaction_info']['user'] = user_details.username
                transaction_date = temp_data['transaction_info']['transaction_date']
                transaction_date_obj = datetime.strptime(
                    transaction_date, '%Y-%m-%dT%H:%M:%S.%fZ')
                temp_data['transaction_info']['transaction_date'] = datetime.strftime(
                    transaction_date_obj, "%d/%m/%Y")
                transaction_fields.append(temp_data)
            return Response({
                "status": "Success",
                "data": transaction_fields
            })
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AppConfigAPI(APIView):
    """
    APIView which will change the percentage value which decides how much points a user gets
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET method which will return the configurations used in the app
        """
        try:
            config_details = AppConfigDB.objects.get(id=1)
            loyalty_data = {
                "loyalty_percent": config_details.loyalty_percent
            }
            return Response({
                "status": "Success",
                "data": loyalty_data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def put(request):
        """
        PUT Method which will update the existing app configurations like loyalty percentage
        """
        try:
            percentage = request.data['loyalty_percent']
            config_details = AppConfigDB.objects.get(id=1)
            config_details.loyalty_percent = percentage
            config_details.save()
            return Response({
                "status": "Success",
                "message": "Configuration updated on the app"
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegisteredUsersPerMonthAPI(APIView):
    """
    APIView which will return the number of registered users per month based on the month selected by the CMS user
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET method which will return the number of registered users per month based on the month selected by the CMS user
        """
        try:
            date_from = request.GET['date_from']
            date_to = request.GET['date_to']
            date_from_obj = make_aware(
                datetime.strptime(date_from, '%Y-%m-%d'))
            date_to_obj = make_aware(datetime.strptime(date_to, '%Y-%m-%d'))
            user_count = 0
            users = User.objects.filter(
                date_joined__range=[date_from_obj, date_to_obj])
            for i in users:
                if i.username != "admin":
                    try:
                        user_details = UserDB.objects.get(user=i)
                    except ObjectDoesNotExist:
                        continue
                    if user_details.user_type in ["google", "facebook", "app"]:
                        user_count += 1
            return Response({
                "status": "Success",
                "data": {
                    "registered_users": user_count
                }
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TotalTransactionsAPI(APIView):
    """
    APIView which will return with the total transactions in a month and year
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET method which will return the total number of transactions that were made in a selected month and year
        """
        try:
            date_from = request.GET['date_from']
            date_to = request.GET['date_to']
            date_from_obj = make_aware(
                datetime.strptime(date_from, '%Y-%m-%d'))
            date_to_obj = make_aware(datetime.strptime(date_to, '%Y-%m-%d'))
            transaction_count = TransactionDB.objects.filter(
                transaction_date__range=[date_from_obj, date_to_obj]).count()
            return Response({
                "status": "Success",
                "data": {
                    "total_transactions": transaction_count
                }
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PointsByLoginTypeAPI(APIView):
    """
    APIView which will return the number of points earned by users of different login types to the analytics dashboard
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.cms_user', raise_exception=True)
    def get(request):
        """
        GET method which will return the number of points earned by users of different login types
        """
        try:
            date_from = request.GET['date_from']
            date_to = request.GET['date_to']
            date_from_obj = make_aware(
                datetime.strptime(date_from, '%Y-%m-%d'))
            date_to_obj = make_aware(datetime.strptime(date_to, '%Y-%m-%d'))
            users = User.objects.filter(
                date_joined__range=[date_from_obj, date_to_obj])
            final_data = [{"login_type": "google", "total_count": 0}, {"login_type": "alpha", "total_count": 0}, {
                "login_type": "facebook", "total_count": 0}, {"login_type": "app", "total_count": 0}]
            for i in users:
                if i.username == "admin":
                    continue
                try:
                    user_details = UserDB.objects.get(user=i.id)
                except ObjectDoesNotExist:
                    continue
                login_type = ""
                if user_details.user_type == "alpha":
                    login_type = "alpha"
                else:
                    login_type = user_details.user_type

                for j in final_data:
                    if j["login_type"] == login_type:
                        j["total_count"] += 1

            return Response({
                "status": "Success",
                "data": {
                    "total_users": final_data
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class EarnedRedeemedPointsAPI(APIView):
    """
    APIView which will return the earned vs redeemed points data for every month in a year
    """

    @staticmethod
    def get(request):
        """
        GET method which will return earned vs redeemed points data for every month in a year
        """
        try:
            year = request.GET['year']
            where = 'YEAR(transaction_date) = %(year)s' % {'year': year}
            transaction_data = TransactionDB.objects.extra(where=[where])
            data = {}
            for i in transaction_data:
                month = int(i.transaction_date.month)
                if not data:
                    data[month] = {}
                    data[month]['earned'] = i.points_applied
                    data[month]['redeemed'] = i.points_deducted
                else:
                    if month in data.keys():
                        data[month]['earned'] += i.points_applied
                        data[month]['redeemed'] += i.points_deducted
                    else:
                        data[month] = {}
                        data[month]['earned'] = i.points_applied
                        data[month]['redeemed'] = i.points_deducted
            return Response({
                "status": "Success",
                "data": {
                    "points_data": data
                }
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProductsSoldAPI(APIView):
    """
    APIView which will return data regarding products sold for a given date range
    """

    @staticmethod
    def get(request):
        """
        GET method which will fetch and return the data regarding products sold for a given date range
        """
        try:
            date_from = request.GET['date_from']
            date_to = request.GET['date_to']
            date_from_obj = make_aware(
                datetime.strptime(date_from, '%Y-%m-%d'))
            date_to_obj = make_aware(datetime.strptime(date_to, '%Y-%m-%d'))
            transaction_data = TransactionDB.objects.filter(
                transaction_date__range=[date_from_obj, date_to_obj])
            data = {}
            for i in transaction_data:
                name = i.product_name
                if not data:
                    data[name] = {}
                    data[name]['sold_units'] = i.quantity
                else:
                    if name in data.keys():
                        data[name]['sold_units'] += i.quantity
                    else:
                        data[name] = {}
                        data[name]['sold_units'] = i.quantity
            return Response({
                "status": "Success",
                "data": {
                    "product_data": data
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
