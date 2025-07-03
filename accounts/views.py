import json
from django.conf import settings
from rest_framework import generics
from django.http import JsonResponse
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from accounts.serializers import RegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework.permissions import AllowAny, IsAuthenticated

# Register a new user.
class RegisterView(generics.CreateAPIView):
    queryset = get_user_model().objects.all()
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

# Login a user (Secure login using http only cookies)
class LoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            data = json.loads(request.body)
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                return JsonResponse({'error': 'Email and password required'}, status=400)
            
            # Authenticate user
            user = authenticate(request, username=email, password=password)
            
            if not user:
                return JsonResponse({'error': 'Invalid credentials, please try again!'}, status=401)
            
            if not user.is_active:
                return JsonResponse({'error': 'This account is inactive!'}, status=401)
            
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)
            
            # Prepare response
            response_data = {
                'success': True,
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email_verified': user.email_verified,
                }
            }
            
            response = JsonResponse(response_data)
            
            # Set secure httpOnly cookies
            access_max_age = int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds())
            refresh_max_age = int(settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds())
            
            # Access token cookie
            response.set_cookie(
                'access_token',
                access_token,
                max_age=access_max_age,
                httponly=True,  # Prevents XSS
                secure=settings.DEBUG is False,  # HTTPS only in production
                samesite='Lax',  # CSRF protection
                path='/'
            )
            
            # Refresh token cookie
            response.set_cookie(
                'refresh_token',
                refresh_token,
                max_age=refresh_max_age,
                httponly=True,
                secure=settings.DEBUG is False,
                samesite='Lax',
                path='/'
            )
            
            return response
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': 'Login failed'}, status=500)

# Refresh access token using httpOnly cookie
class RefreshTokenView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        
        if not refresh_token:
            return JsonResponse({'error': 'Refresh token not found'}, status=401)
        
        try:
            # Validate and refresh token
            refresh = RefreshToken(refresh_token)
            new_access_token = str(refresh.access_token)
            
            response_data = {'success': True}
            response = JsonResponse(response_data)
            
            # Set new access token cookie
            access_max_age = int(settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds())
            response.set_cookie(
                'access_token',
                new_access_token,
                max_age=access_max_age,
                httponly=True,
                secure=settings.DEBUG is False,
                samesite='Lax',
                path='/'
            )
            
            return response
            
        except TokenError:
            return JsonResponse({'error': 'Invalid refresh token'}, status=401)
        except Exception as e:
            return JsonResponse({'error': 'Token refresh failed'}, status=401)

# Secure logout - clear cookies 
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            # Try to get refresh token from cookie for potential blacklisting
            refresh_token = request.COOKIES.get('refresh_token')
            
            if refresh_token:
                try:
                    # Optionally blacklist the refresh token
                    token = RefreshToken(refresh_token)
                except TokenError:
                    # Token was already invalid, that's fine
                    pass
            
            response = JsonResponse({'success': True, 'message': 'Logged out successfully'})
            
            # Clear cookies
            response.delete_cookie('access_token', path='/')
            response.delete_cookie('refresh_token', path='/')
            
            return response
            
        except Exception as e:
            # Even if there's an error, still clear cookies
            response = JsonResponse({'success': True, 'message': 'Logged out successfully'})
            response.delete_cookie('access_token', path='/')
            response.delete_cookie('refresh_token', path='/')
            return response

# Get user/profile data (Get current user info)
class MeView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Authentication required'}, status=401)
        
        return JsonResponse({
            'user': {
                'id': str(request.user.id),
                'email': request.user.email,
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
                'email_verified': getattr(request.user, 'email_verified', False),
            }
        })