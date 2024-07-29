from django.db import models
from .validators import validate_icon_extension


class ProductDB(models.Model):
    """
    Product DB with product information
    """
    name = models.CharField(max_length=200, blank=False, null=False)
    description = models.TextField(null=True)
    price = models.DecimalField(
        default=0.00, decimal_places=2, null=False, blank=False, max_digits=9)
    image = models.ImageField(
        upload_to='products/', blank=True, null=True)
    info_link = models.URLField()
    disable_product = models.BooleanField(
        default=False, blank=False, null=False)

    def delete(self):
        self.image.delete()
        super(ProductDB, self).delete()


class OfferCategoryDB(models.Model):
    """
    Offers Category model where category data is stored
    """
    category_name = models.CharField(max_length=200, blank=False, null=False)
    disable_category = models.BooleanField(
        default=False, blank=False, null=False)
    icon = models.FileField(upload_to='icons/', blank=True,
                            null=True, validators=[validate_icon_extension])

    def __str__(self):
        return u'{0}'.format(self.category_name)

    def delete(self):
        """
        Custom delete function which will delete the image icon as well
        """
        self.icon.delete()
        super(OfferCategoryDB, self).delete()


class OffersDB(models.Model):
    """
    Offers DB with offer information
    """
    category = models.ForeignKey(OfferCategoryDB, on_delete=models.CASCADE)
    name = models.CharField(max_length=200, blank=False, null=False)
    description = models.TextField(null=True)
    offer_start_date = models.DateField()
    offer_end_date = models.DateField()
    image_1 = models.ImageField(
        upload_to='offers/', default="offers/default-offers.png", blank=True, null=True)
    image_2 = models.ImageField(
        upload_to='offers/', default="offers/default-offers.png", blank=True, null=True)
    image_3 = models.ImageField(
        upload_to='offers/', default="offers/default-offers.png", blank=True, null=True)
    disable_offer = models.BooleanField(
        default=False, blank=False, null=False)

    def delete(self):
        if "default-offers.png" in self.image_1.path:
            pass
        else:
            self.image_1.delete()
        if "default-offers.png" in self.image_2.path:
            pass
        else:
            self.image_2.delete()
        if "default-offers.png" in self.image_3.path:
            pass
        else:
            self.image_3.delete()
        super(OffersDB, self).delete()


class FaqDB(models.Model):
    """
    Model which stores the faq question and answer details
    """
    question = models.TextField()
    answer = models.TextField(null=True, blank=True)
    disable_faq = models.BooleanField(default=False, blank=False, null=False)
