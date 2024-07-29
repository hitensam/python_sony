from django.urls import path
from .views import AppConfigAPI, EarnedRedeemedPointsAPI, FaqAPI, OffersAPI, OffersCategoryAPI, PointsByLoginTypeAPI, ProductAPI, ProductsSoldAPI, RegisteredUsersPerMonthAPI, SendNotificationAPI, TotalTransactionsAPI, TransactionAPI, UsersAPI

urlpatterns = [
    path('product', ProductAPI.as_view()),
    path('offers', OffersAPI.as_view()),
    path('faq', FaqAPI.as_view()),
    path('category', OffersCategoryAPI.as_view()),
    path('users', UsersAPI.as_view()),
    path('notification', SendNotificationAPI.as_view()),
    path('transaction', TransactionAPI.as_view(), name="cms_tran_details"),
    path('app-config', AppConfigAPI.as_view(), name="cms_app_config"),
    path('analytics/registered-users', RegisteredUsersPerMonthAPI.as_view()),
    path('analytics/total-transaction', TotalTransactionsAPI.as_view()),
    path('analytics/user-points', PointsByLoginTypeAPI.as_view()),
    path('analytics/points-data', EarnedRedeemedPointsAPI.as_view()),
    path('analytics/products-sold', ProductsSoldAPI.as_view())
]
