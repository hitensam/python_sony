from django.contrib.auth.decorators import permission_required
from django.contrib.auth.models import User
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from api.views import PointsAPI, RedeemPointsAPI


class UserPointsPOSAPI(APIView):
    """
    API View which will fetch users points and display it for pos
    """

    permission_classes = [permissions.IsAuthenticated]

    @staticmethod
    @permission_required("api.store_user", raise_exception=True)
    def get(request):
        """
        GET Method which will fetch users points and display it for pos
        """
        try:
            email = request.GET.get("email")
            user_obj = User.objects.get(email=email)
            points_view = PointsAPI()
            request.user = user_obj
            view_response = points_view.get(request)
            return view_response

        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EarnPointsPOSAPI(APIView):
    """
    API View which will allow users to earn points from pos
    """

    permission_classes = [permissions.IsAuthenticated]

    @staticmethod
    @permission_required("api.store_user", raise_exception=True)
    def put(request):
        """
        PUT method which will allow users to earn points from pos
        """
        try:
            invoice_id = request.data.get("invoice")
            products = request.data.get("products")
            email = request.data.get("email")
            data_txt = ""
            for product in products:
                if data_txt == "":
                    data_txt += f"invoice:{invoice_id},Name:{product['name']},Price:{product['cost']},quantity:{product['quantity']}"
                else:
                    data_txt += f",invoice:{invoice_id},Name:{product['name']},Price:{product['cost']},quantity:{product['quantity']}"
            user_details = User.objects.get(email=email)

            points_view = PointsAPI()
            request.user = user_details
            request.data["data"] = data_txt
            view_response = points_view.put(request)

            return view_response
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RedeemPointsPOSAPI(APIView):
    """
    API View which will redeem points for a user and reflect it on the user's point balance
    """

    permission_classes = [permissions.IsAuthenticated]

    @staticmethod
    @permission_required("api.store_user", raise_exception=True)
    def put(request):
        """
        PUT method which will redeem and update the user's points accordingly
        """

        try:
            invoice_id = request.data.get("invoice")
            products = request.data.get("products")
            email = request.data.get("email")
            data_txt = ""

            for product in products:
                if data_txt == "":
                    data_txt += f"invoice:{invoice_id},Name:{product['name']},Price:{product['price']},quantity:{product['quantity']},amountApplied:{product['amount_applied']}"
                else:
                    data_txt += f",invoice:{invoice_id},Name:{product['name']},Price:{product['price']},quantity:{product['quantity']},amountApplied:{product['amount_applied']}"
            user_details = User.objects.get(email=email)

            points_view = RedeemPointsAPI()
            request.user = user_details
            request.data["data"] = data_txt
            view_response = points_view.put(request)

            return view_response
        except Exception as e:
            return Response(
                {"status": "Failed", "message": e.args},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
