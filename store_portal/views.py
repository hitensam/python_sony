from django.contrib.auth.decorators import permission_required
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from api.helpers import online_sync_points
from api.models import PointsDB, TransactionDB, VoucherCodeDB
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
import decimal
from datetime import datetime
import pytz


class VoucherAPI(APIView):
    """
    APIView which will get the voucher details for a voucher code
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.store_user', raise_exception=True)
    def get(request):
        """
        GET method used to fetch the voucher code details
        """
        try:
            voucher_code = request.GET['code']
            voucher_details = VoucherCodeDB.objects.get(
                voucher_code=voucher_code)
            current_time = datetime.now(pytz.UTC)
            voucher_create_date = voucher_details.voucher_created_date
            diff = (current_time - voucher_create_date).total_seconds()/60
            if voucher_details:
                if voucher_details.redeemed == False and int(diff) < 10:
                    return Response({
                        "status": "Success",
                        "data": {
                            "voucher_code": voucher_details.voucher_code,
                            "username": voucher_details.user.username,
                            "email": voucher_details.user.email,
                            "voucher_value": f"Dhs {voucher_details.voucher_value}"
                        }
                    }, status=status.HTTP_200_OK)
                else:
                    if diff > 10:
                        voucher_details.delete()
                        return Response({
                            "status": "Failed",
                            "message": "Voucher code has expired"
                        }, status=status.HTTP_404_NOT_FOUND)
                    return Response({
                        "status": "Failed",
                        "message": "Voucher code has already been redeemed"
                    }, status=status.HTTP_404_NOT_FOUND)
            else:
                return Response({
                    "status": "Failed",
                    "message": "Invalid voucher code"
                }, status=status.HTTP_404_NOT_FOUND)
        except ObjectDoesNotExist:
            return Response({
                "status": "Failed",
                "message": "Invalid voucher code"
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.store_user', raise_exception=True)
    def put(request):
        """
        PUT method which will claim the voucher
        """
        try:
            voucher_code = request.data['code']
            voucher_details = VoucherCodeDB.objects.get(
                voucher_code=voucher_code)
            if voucher_details:
                if voucher_code != "v8OSXDqt3gTABnuljgFX".strip():  # ! Remove after testing
                    voucher_details.redeemed = True
                    voucher_details.voucher_redeem_date = timezone.now()
                    voucher_details.save()
                return Response({
                    "status": "Success",
                    "message": "Voucher value has been redeemed"
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "status": "Failed",
                    "message": "Invalid voucher code"
                }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReturnProductsAPI(APIView):
    """
    APIView which will deduct/return points to a loyalty user
    """

    permission_classes = (permissions.IsAuthenticated,)

    @staticmethod
    @permission_required('api.store_user', raise_exception=True)
    def get(request):
        """
        GET method which will be used to get the list of products from an invoice id
        """
        try:
            invoice_id = request.GET['invoice_id']
            transaction = TransactionDB.objects.filter(invoice_id=invoice_id)
            product_details = []
            for i in transaction:
                product_data = {}
                if not i.returned:
                    product_data['product_id'] = i.id
                    product_data['product_name'] = i.product_name
                    product_data['product_cost'] = i.product_cost
                    product_details.append(product_data)
            if not transaction:
                return Response({
                    "status": "Failed",
                    "message": "Invoice ID not found"
                }, status=status.HTTP_404_NOT_FOUND)
            if product_details == []:
                return Response({
                    "status": "Failed",
                    "message": "No products available to return"
                }, status=status.HTTP_404_NOT_FOUND)
            return Response({
                "status": "Success",
                "data": product_details
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    @permission_required('api.store_user', raise_exception=True)
    def put(request):
        """
        PUT method which will update which product was returned
        """
        try:
            invoice_id = request.data['invoice_id']
            updated_info = request.data['product_info']
            modified_points = 0
            user = None
            for i in updated_info:
                product_id = i["product_id"]
                # product_name = i["product_name"]   #! Remove after testing
                # product_cost = i["product_cost"]   #! Remove after testing
                transaction = TransactionDB.objects.get(id=product_id)
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

            # ! Enable after app gets approved
            online_sync_points(user.email, user_points, deduct=True)

            return Response({
                "status": "Success",
                "message": "Points have been updated in the users account"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "status": "Failed",
                "message": e.args
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
