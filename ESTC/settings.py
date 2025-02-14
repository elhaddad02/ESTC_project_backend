import os
import ssl
from datetime import timedelta
from pathlib import Path

import environ
from django.utils.translation import gettext_lazy as _


env = environ.Env()
environ.Env.read_env()

BASE_DIR = Path(__file__).resolve(strict=True).parent.parent


SECRET_KEY = env('DJANGO_SECRET_KEY', default='django-insecure-m4o_rb@3=2^-px1mi2$44#ozmv2##vjp$_34#rq+wk3&))1x50')


DEBUG = True


ALLOWED_HOSTS = [
    'app.universfrancesucces.com',
    'localhost',
    '127.0.0.1',
    '192.162.68.92',
    'api.ip.pn',
]


INSTALLED_APPS = [
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'drf_spectacular',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'drf_yasg',
    'rosetta',
    'authentication',
    'students',
    'parents',
    "django_extensions"
]

ASGI_APPLICATION = 'ESTC.asgi.application'

CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}

AUTH_USER_MODEL = 'authentication.User'

REST_FRAMEWORK = {
    'NON_FIELD_ERRORS_KEY': 'error',
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.AllowAny',
    ),
    'EXCEPTION_HANDLER': 'rest_framework.views.exception_handler',
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'My API',
    'DESCRIPTION': 'API Documentation',
    'VERSION': '1.0.0',
}

SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
        },
    },
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=600),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # cors middleware,
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ESTC.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],  # Ajouter cette ligne

        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ESTC.wsgi.application'

# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME':  BASE_DIR / 'db.sqlite3',
    }
}

#CORS

CORS_ALLOWED_ORIGINS = [
    "https://app.universfrancesucces.com",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
]

CORS_ALLOW_CREDENTIALS = True


AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


LANGUAGE_CODE = 'fr'

LANGUAGES = [
    ('en', _('English')),
    ('fr', _('French')),
]

LOCALE_PATHS = [
    BASE_DIR / 'locale/',
]

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = '/media/'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST='smtp.gmail.com'
EMAIL_PORT=587 #2525
EMAIL_USE_TLS=True
EMAIL_HOST_USER='ikram2029at@gmail.com'
EMAIL_HOST_PASSWORD='yhdl mzvb jjcy jjjb'
DEFAULT_FROM_EMAIL='from@example.com'


#EMAIL_BACKEND = env('EMAIL_BACKEND')
#EMAIL_HOST = env('EMAIL_HOST')
#EMAIL_PORT = env.int('EMAIL_PORT')
#EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=True)
#EMAIL_HOST_USER = env('EMAIL_HOST_USER')
#EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
#DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')

# Handle SSL context for the email backend if necessary
ssl._create_default_https_context = ssl._create_unverified_context

if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
