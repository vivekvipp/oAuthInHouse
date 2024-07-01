from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('gamp_auth/', include('gamp_auth.urls')),
]