from django.urls import path
from .views import ReturnProductsAPI, VoucherAPI

urlpatterns = [
    path('voucher', VoucherAPI.as_view()),
    path('return', ReturnProductsAPI.as_view())
]
