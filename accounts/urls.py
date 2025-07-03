from django.urls import path
from .views import RegisterView, LoginView, RefreshTokenView, LogoutView, MeView

urlpatterns = [
    path('token/refresh/', RefreshTokenView.as_view(), name='token_refresh'),
    path('signup/', RegisterView.as_view(), name='signup'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('login/', LoginView.as_view(), name='login'),
    path('me/', MeView.as_view(), name='me'),
]