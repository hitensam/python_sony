"""sony URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("cms/", include("cms.urls")),
    path("app/", include(("api.urls", "api"), namespace="v1")),
    path("v2/app/", include(("api.urls", "api"), namespace="v2")),
    path("store/", include("store_portal.urls")),
    path("online/", include("online.urls")),
    path("v2/pos/", include("api_pos.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
