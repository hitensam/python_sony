import os
from rest_framework import serializers
from .validators import validate_icon_extension
from .models import FaqDB, OfferCategoryDB, OffersDB, ProductDB


class ProductSerializer(serializers.ModelSerializer):
    """
    Class used to serialize the data and validate which will then be stored in DB
    """

    name = serializers.CharField(required=True)
    description = serializers.CharField()
    price = serializers.DecimalField(
        required=True, max_digits=9, decimal_places=2)
    image = serializers.ImageField(required=True)
    info_link = serializers.URLField(required=True)
    disable_product = serializers.BooleanField()

    def create(self, validated_data):
        """
        Function to create new record in DB
        """
        product = ProductDB.objects.create(name=validated_data['name'], description=validated_data['description'], price=validated_data['price'], image=validated_data['image'],
                                           info_link=validated_data['info_link'], disable_product=validated_data['disable_product'])
        return product

    def update(self, instance, validated_data):
        """
        Function to update data to DB
        """

        for (key, value) in validated_data.items():
            if key == "image":
                os.remove(instance.image.path)
            setattr(instance, key, value)
        instance.save()
        return instance

    class Meta:
        """
        Meta class with details of which model and fields to be serialized
        """
        model = ProductDB
        fields = ['name', 'description', 'price', 'image',
                  'info_link', 'disable_product']


class OfferCategorySerializer(serializers.ModelSerializer):
    """
    Class used to serialize the data and validate which will then be stored in DB
    """
    category_name = serializers.CharField()
    disable_category = serializers.BooleanField(default=False)
    icon = serializers.FileField(validators=[validate_icon_extension])

    def create(self, validated_data):
        """
        Function to create new record in DB
        """
        category = OfferCategoryDB.objects.create(
            category_name=validated_data['category_name'], disable_category=validated_data['disable_category'], icon=validated_data['icon'])
        return category

    def update(self, instance, validated_data):
        """
        Function to update data to DB
        """
        for (key, value) in validated_data.items():
            if key == "icon":
                path = getattr(getattr(instance, key), 'path')
                os.remove(path)
            setattr(instance, key, value)
        instance.save()
        return instance

    class Meta:
        """
        Meta class with details of which model and fields to be serialized
        """
        model = OfferCategoryDB
        fields = ['category_name', 'disable_category', 'icon']


class OfferSerializer(serializers.ModelSerializer):
    """
    Class used to serialize the data and validate which will then be stored in DB
    """

    category = serializers.PrimaryKeyRelatedField(
        required=True, queryset=OfferCategoryDB.objects.all())
    name = serializers.CharField()
    description = serializers.CharField()
    offer_start_date = serializers.DateField()
    offer_end_date = serializers.DateField()
    image_1 = serializers.ImageField(
        default="offers/default-offers.png")
    image_2 = serializers.ImageField(
        default="offers/default-offers.png")
    image_3 = serializers.ImageField(
        default="offers/default-offers.png")
    disable_offer = serializers.BooleanField()

    def create(self, validated_data):
        """
        Function to create new record in DB
        """
        offer = OffersDB.objects.create(category=validated_data['category'], name=validated_data['name'], description=validated_data['description'], offer_start_date=validated_data['offer_start_date'],
                                        offer_end_date=validated_data['offer_end_date'], image_1=validated_data['image_1'], image_2=validated_data['image_2'], image_3=validated_data['image_3'], disable_offer=validated_data['disable_offer'])
        return offer

    def update(self, instance, validated_data):
        """
        Function to update data to DB
        """

        for (key, value) in validated_data.items():
            if key == "image_1" or key == "image_2" or key == "image_3":
                path = getattr(getattr(instance, key), 'path')
                if not("default-offers.png" in path):
                    os.remove(path)

            setattr(instance, key, value)
        instance.save()
        return instance

    class Meta:
        """
        Meta class with details of which model and fields to be serialized
        """
        model = OffersDB
        fields = ['category', 'name', 'description', 'offer_start_date',
                  'offer_end_date', 'image_1', 'image_2', 'image_3', 'disable_offer']


class FaqSerializer(serializers.ModelSerializer):
    """
    Class used to serialize the data and validate which will then be stored in DB
    """
    question = serializers.CharField()
    answer = serializers.CharField()
    disable_faq = serializers.BooleanField(default=False)

    def create(self, validated_data):
        """
        Function to create new record in DB
        """
        faq = FaqDB.objects.create(
            question=validated_data['question'], answer=validated_data['answer'], disable_faq=validated_data['disable_faq'])
        return faq

    def update(self, instance, validated_data):
        """
        Function to update data to DB
        """
        for (key, value) in validated_data.items():
            setattr(instance, key, value)
        instance.save()
        return instance

    class Meta:
        """
        Meta class with details of which model and fields to be serialized
        """
        model = FaqDB
        fields = ['question', 'answer', 'disable_faq']
