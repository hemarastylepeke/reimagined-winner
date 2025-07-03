# admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth import get_user_model

User = get_user_model()

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    # Fields to display in the user list
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'created_at')
    
    # Fields to filter by in the admin sidebar
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'created_at')
    
    # Fields to search by
    search_fields = ('email', 'first_name', 'last_name')
    
    # Default ordering
    ordering = ('-created_at',)
    
    # Fields to display when editing a user
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    
    # Fields to display when adding a new user
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'first_name', 'last_name', 'is_active'),
        }),
    )
    
    # Make created_at and updated_at read-only
    readonly_fields = ('created_at', 'updated_at', 'last_login')