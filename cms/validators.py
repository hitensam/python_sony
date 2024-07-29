import os
from django.core.exceptions import ValidationError
from django.conf import settings


def validate_icon_extension(value):
    ext = os.path.splitext(value.name)[1]
    valid_extensions = [".png"]
    if not ext.lower() in valid_extensions:
        raise ValidationError(
            'Unsupported file extension for icons. Please upload an png file for icons.')


def validate_product_file_exists(value):
    media_root = getattr(settings, 'MEDIA_ROOT', '')
    file_name = value.name
    if '@' in file_name:
        file_name = file_name.replace('@', '')
    file_path = media_root+"/products/"+file_name
    status = os.path.isfile(file_path)
    if status:
        raise ValidationError("File already exists")


def validate_offers_file_exists(value):
    media_root = getattr(settings, 'MEDIA_ROOT', '')
    file_name = value.name
    if '@' in file_name:
        file_name = file_name.replace('@', '')
    file_path = media_root+"/products/"+file_name
    status = os.path.isfile(file_path)
    if status:
        raise ValidationError("File already exists")
