from django.urls import path

from .views import EarnPointsPOSAPI, RedeemPointsPOSAPI, UserPointsPOSAPI

urlpatterns = [
    path("user-points", UserPointsPOSAPI.as_view()),
    path("earn-points", EarnPointsPOSAPI.as_view()),
    path("redeem-points", RedeemPointsPOSAPI.as_view()),
]
