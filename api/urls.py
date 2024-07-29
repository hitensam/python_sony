from django.urls import path

from .views import (AlphaUniverseAPI, ChangePasswordAPI, CountryCheckAPI,
                    DeleteUserAPI, EmailCheckAPI, FCMTokenAPI,
                    FilterOfferByCategoryAPI, ForgetPasswordChangeAPI,
                    GetCategoryAPI, GetFaqAPI, GetOffersAPI, GetProductAPI,
                    GetUserTransactionAPI, LoginAPI, LogoutAPI, PointsAPI,
                    ProfileAPI, RedeemPointsAPI, RegisterAPI, SendOtpAPI,
                    SonyWorldAPI, VerifyOtpAPI, VoucherAPI, SSOLoginView,
                    ProfileTransferAPI,)


urlpatterns = [
    path("register", RegisterAPI.as_view()),
    path("check-email", EmailCheckAPI.as_view()),
    path("check-country", CountryCheckAPI.as_view()),
    path("login", LoginAPI.as_view()),
    path("profile-transfer", ProfileTransferAPI.as_view()),
    path("sso-login", SSOLoginView.as_view()),
    path("change-password", ChangePasswordAPI.as_view()),
    path("profile", ProfileAPI.as_view()),
    path("logout", LogoutAPI.as_view()),
    path("send-otp", SendOtpAPI.as_view()),
    path("verify-otp", VerifyOtpAPI.as_view()),
    path("product", GetProductAPI.as_view()),
    path("offers", GetOffersAPI.as_view()),
    path("offer-by-category", FilterOfferByCategoryAPI.as_view()),
    path("category", GetCategoryAPI.as_view()),
    path("faqs", GetFaqAPI.as_view()),
    path("forget-password", ForgetPasswordChangeAPI.as_view()),
    path("voucher", VoucherAPI.as_view()),
    path("redeem", RedeemPointsAPI.as_view()),
    path("points", PointsAPI.as_view(), name="api_points"),
    path("alpha", AlphaUniverseAPI.as_view()),
    path("transaction", GetUserTransactionAPI.as_view()),
    path("fcm-token", FCMTokenAPI.as_view()),
    path("user-delete", DeleteUserAPI.as_view()),
    path("user-details", SonyWorldAPI.as_view()),
]
