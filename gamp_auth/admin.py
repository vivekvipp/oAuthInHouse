# gamp_auth/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import Group
from .models import User, OTP
from .forms import CustomUserCreationForm, CustomUserChangeForm


class CustomUserAdmin(BaseUserAdmin):
    # The forms to add and change user instances
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm

    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserAdmin
    list_display = ('email', 'mobile_no', 'username', 'is_staff', 'is_superuser', 'is_active')
    list_filter = ('is_staff', 'is_superuser', 'is_active')
    fieldsets = (
        (None, {'fields': ('email', 'mobile_no', 'username', 'password')}),
        ('Permissions', {'fields': ('is_staff', 'is_superuser', 'is_active')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'mobile_no', 'username', 'password1', 'password2')}
         ),
    )
    search_fields = ('email', 'mobile_no', 'username')
    ordering = ('email',)
    filter_horizontal = ()


admin.site.register(User, CustomUserAdmin)
admin.site.unregister(Group)


# Register the OTP model
class OTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'created_at', 'is_used')
    list_filter = ('is_used',)
    search_fields = ('user__username', 'otp')


admin.site.register(OTP, OTPAdmin)
