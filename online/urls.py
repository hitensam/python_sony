from django.urls import path
from .views import *

urlpatterns = [
    # path('login', LoginAPI.as_view()),
    path('verify', VerifyEmailAPI.as_view()),
    path('points-calculate', PointsCalculateAPI.as_view()),
    path('user-points', UserPointsAPI.as_view()),
    path('earn-points', EarnPointsAPI.as_view()),
    path('redeem-points', RedeemPointsAPI.as_view()),
    path('return', ReturnAPI.as_view()),
]
