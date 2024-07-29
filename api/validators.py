import os
from django.core.exceptions import ValidationError


def validate_max_digit(value):
    if value > 100:
        raise ValidationError(
            'Loyalty percentage value should not exceed 100%')
