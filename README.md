# EyesOnly Django App

EyesOnly is a Django app that provides encrypted image workflows, device authentication, and REST APIs.

## Install

You can install the package from PyPI with:

```bash
pip install django-eyesonly
```

For local development from source:

```bash
pip install -e .
```

## Add EyesOnly to Your Django Project

In your Django project's [settings.py](settings.py), add the required apps:

```python
INSTALLED_APPS = [
    # Django defaults...
    'eyesonly',
    'fcm_django',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
]
```

## Configure Required settings.py Values

Also in [settings.py](settings.py), configure encrypted image storage paths:

```python
ENCRYPTED_IMAGES_ROOT = '/var/www/eyesonly/encrypted-images/'
ENCRYPTED_IMAGES_INTERNAL_LOCATION = '/api/internal-encrypted-images/'
```

What these mean:
- `ENCRYPTED_IMAGES_ROOT`: filesystem path where encrypted image blobs are stored.
- `ENCRYPTED_IMAGES_INTERNAL_LOCATION`: internal URL prefix used by reverse proxy internal redirects for protected blob delivery.

Recommended production pattern is to use environment variables:

```python
import os

ENCRYPTED_IMAGES_ROOT = os.getenv('ENCRYPTED_IMAGES_ROOT', '/var/www/eyesonly/encrypted-images/')
ENCRYPTED_IMAGES_INTERNAL_LOCATION = os.getenv('ENCRYPTED_IMAGES_INTERNAL_LOCATION', '/api/internal-encrypted-images/')
```

## Firebase / FCM Setup in settings.py

In [settings.py](settings.py), initialize Firebase Admin and configure `fcm_django`:

```python
import os
import firebase_admin
from firebase_admin import credentials

firebase_credentials_path = os.getenv('FIREBASE_CREDENTIALS_PATH', '')

FIREBASE_APP = None
if firebase_credentials_path:
    cred = credentials.Certificate(firebase_credentials_path)
    FIREBASE_APP = firebase_admin.initialize_app(cred)

FCM_DJANGO_SETTINGS = {
    'DEFAULT_FIREBASE_APP': None,
    'APP_VERBOSE_NAME': 'Eyes Only FCM',
    'ONE_DEVICE_PER_USER': False,
    'DELETE_INACTIVE_DEVICES': False,
    'EMIT_DEVICE_DEACTIVATED_SIGNAL': False,
}
```

## URL Setup

Include the app URLs in your project URLconf (example):

```python
from django.urls import include, path

urlpatterns = [
    path('api/', include('eyesonly.api.urls')),
]
```

## Run Migrations

```bash
python manage.py migrate
```

## Quick Start Checklist

1. Install package: `pip install django-eyesonly`
2. Add apps in [settings.py](settings.py) `INSTALLED_APPS`
3. Configure encrypted image settings in [settings.py](settings.py)
4. Configure Firebase credentials and `FCM_DJANGO_SETTINGS` in [settings.py](settings.py)
5. Include `eyesonly.api.urls` in your project URLs
6. Run migrations

## Notes

- Keep Firebase service account JSON files out of git.
- Ensure the process user can read/write `ENCRYPTED_IMAGES_ROOT`.
- Ensure your reverse proxy internal location matches `ENCRYPTED_IMAGES_INTERNAL_LOCATION`.
