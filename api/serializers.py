from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

from .models import TransactionDB, UserDB


class UserSerializer(serializers.ModelSerializer):
    """
    Class which will serialize the data for user registeration
    """
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    username = serializers.CharField(
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(
        required=True,
        min_length=8
    )
    first_name = serializers.CharField(
        required=True
    )
    last_name = serializers.CharField(
        required=True
    )
    user_type = serializers.CharField(required=True)
    promotion_consent = serializers.BooleanField(default=False)
    # country = serializers.CharField(required=False)
    country = serializers.CharField(required=False)
    nationality = serializers.CharField(required=False)

    def create(self, validated_data):
        user = User.objects.create_user(
            validated_data['username'], validated_data['email'], validated_data['password'])
        user.first_name = validated_data['first_name']
        user.last_name = validated_data['last_name']
        user.save()
        UserDB.objects.create(
            user=user,
            country=validated_data['country'],
            nationality=validated_data.get('nationality'),
            user_type=validated_data['user_type'],
            promotion_consent=validated_data['promotion_consent']
        )
        return user

    class Meta:
        """
        Meta class with details of which model and fields to be serialized
        """
        model = UserDB
        fields = ['username', 'email', 'first_name',
                  'last_name', 'password', 'user_type', 'promotion_consent', 'country', 'nationality']


class TransactionSerializer(serializers.ModelSerializer):
    """
    Class which will serialize the data for transaction model
    """

    invoice_id = serializers.CharField(required=True)
    user = serializers.PrimaryKeyRelatedField(
        required=True, queryset=User.objects.all())
    product_name = serializers.CharField()
    product_cost = serializers.DecimalField(
        required=True, max_digits=11, decimal_places=4)
    points_applied = serializers.DecimalField(
        default=0.0000, max_digits=11, decimal_places=4)
    points_deducted = serializers.DecimalField(
        default=0.0000, max_digits=11, decimal_places=4)
    quantity = serializers.IntegerField(default=1)
    returned = serializers.BooleanField(default=False)

    def create(self, validated_data):
        transaction = TransactionDB.objects.create(invoice_id=validated_data['invoice_id'], user=validated_data['user'], product_name=validated_data['product_name'], product_cost=validated_data[
                                                   'product_cost'], points_applied=validated_data['points_applied'], points_deducted=validated_data['points_deducted'], quantity=validated_data['quantity'], returned=validated_data['returned'])
        return transaction

    class Meta:
        """
        Meta class with details of which model and fields to be serialized
        """
        model = TransactionDB
        fields = ['invoice_id', 'user', 'product_name',
                  'product_cost', 'points_applied', 'points_deducted', 'quantity', 'returned']
