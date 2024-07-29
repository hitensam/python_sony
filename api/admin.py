from django.contrib import admin
from .models import AppConfigDB, EnabledCountriesDB, TransactionDB, UserDB, VoucherCodeDB, PointsDB

admin.site.site_header = "Sony Loyalty App Admin Page"


class UserDBAdmin(admin.ModelAdmin):
    """
    Specify the layout for user db model in admin page
    """
    list_display = ('user_email', 'user_type',
                    'fcm_token', 'promotion_consent')
    search_fields = ('user__email',)
    list_filter = ('user_type',)

    def user_email(self, obj):
        return obj.user.email


class VoucherCodeDBAdmin(admin.ModelAdmin):
    """
    Specify the layout for user db model in admin page
    """
    list_display = ('user_email', 'voucher_code', 'voucher_created_date',
                    'voucher_value', 'redeemed', 'voucher_redeem_date')

    def user_email(self, obj):
        return obj.user.email


class PointsDBAdmin(admin.ModelAdmin):
    """
    Specify the layout for user db model in admin page
    """
    list_display = ('user_email', 'point_balance',
                    'points_date', 'last_update')
    readonly_fields = ('last_update',)
    search_fields = ['user__email']

    def user_email(self, obj):
        return obj.user.email


class TransactionDBAdmin(admin.ModelAdmin):
    """
    Specify the layout for user db model in admin page
    """
    list_display = ('invoice_id', 'user_email', 'product_name', 'product_cost',
                    'points_applied', 'points_deducted', 'quantity', 'returned', 'transaction_date')
    search_fields = ('invoice_id', 'user__email',)

    def user_email(self, obj):
        return obj.user.email


class AppConfigDBAdmin(admin.ModelAdmin):
    """
    Specify the layout for user db model in admin page
    """
    list_display = ('loyalty_percentage',)

    def loyalty_percentage(self, obj):
        return obj.loyalty_percent

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(UserDB, UserDBAdmin)
admin.site.register(VoucherCodeDB, VoucherCodeDBAdmin)
admin.site.register(PointsDB, PointsDBAdmin)
admin.site.register(TransactionDB, TransactionDBAdmin)
admin.site.register(AppConfigDB, AppConfigDBAdmin)
admin.site.register(EnabledCountriesDB)
