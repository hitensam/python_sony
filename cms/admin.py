from django.contrib import admin
from .models import FaqDB, OfferCategoryDB, OffersDB, ProductDB


class ProductDBAdmin(admin.ModelAdmin):
    """
    Specify the layout for product db model in admin page
    """
    list_display = ('name', 'description', 'price', 'image', 'info_link',
                    'disable_product')


class OffersDBAdmin(admin.ModelAdmin):
    """
    Specify the layout for offers db model in admin page
    """
    list_display = ('category_name', 'name', 'description', 'offer_start_date',
                    'offer_end_date', 'image_1', 'image_2', 'image_3', 'disable_offer')

    def category_name(self, obj):
        return obj.category.category_name


class FaqDBAdmin(admin.ModelAdmin):
    """
    Specify the layout for faq db model in admin page 
    """
    list_display = ('question', 'answer', 'disable_faq')


class CategoryOffersAdmin(admin.ModelAdmin):
    """
    Specify the layout for Category offers db model in admin page
    """
    list_display = ('category_name', 'icon')


admin.site.register(ProductDB, ProductDBAdmin)
admin.site.register(OffersDB, OffersDBAdmin)
admin.site.register(FaqDB, FaqDBAdmin)
admin.site.register(OfferCategoryDB, CategoryOffersAdmin)
