import hashlib
from datetime import timedelta

from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from rest_framework import authentication
from rest_framework import exceptions

from eyesonly.models import Device, DeviceAuthToken

'''
So why both exist:
Bootstrap/auth onboarding: identify device enough to start challenge flow
Post-login/session: enforce cryptographically strong, revocable token auth

You can think of it as:
DeviceAuthentication = “who do you say you are?”
DeviceTokenAuthentication = “prove it with a valid secret token”
'''


class DeviceAuthentication(authentication.BaseAuthentication):
    keyword = 'X-Device-Identifier'

    def authenticate(self, request):
        # Device requests are not Django user logins. The authenticated device is
        # returned in request.auth while request.user stays anonymous.
        user = AnonymousUser()

        device_identifier = request.META.get('HTTP_X_DEVICE_IDENTIFIER')
        if not device_identifier:
            return None

        try:
            device = Device.objects.get(device_identifier=device_identifier)
        except Device.DoesNotExist:
            # Return None so the view (not this authenticator) decides how to respond.
            # Raising here would leak whether the identifier is registered.
            return None

        return (user, device)

    def authenticate_header(self, request):
        return self.keyword


class DeviceTokenAuthentication(authentication.BaseAuthentication):
    keyword = 'Bearer'

    def authenticate(self, request):
        # Only attempt device-token auth for requests that identify themselves
        # as device calls. This allows JWT bearer auth to coexist on endpoints
        # that support both manager users and devices.
        expected_identifier = request.META.get('HTTP_X_DEVICE_IDENTIFIER')
        if not expected_identifier:
            return None

        authorization_header = authentication.get_authorization_header(request).split()
        if not authorization_header:
            return None

        if authorization_header[0].lower() != self.keyword.lower().encode():
            return None

        if len(authorization_header) != 2:
            raise exceptions.AuthenticationFailed('Invalid bearer token header.')

        try:
            raw_token = authorization_header[1].decode('utf-8')
        except UnicodeDecodeError:
            raise exceptions.AuthenticationFailed('Invalid bearer token header.')
        token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

        now = timezone.now()
        try:
            device_auth_token = DeviceAuthToken.objects.select_related('device').get(
                token_hash=token_hash,
                is_revoked=False,
                expires_at__gt=now,
            )
        except DeviceAuthToken.DoesNotExist as exc:
            raise exceptions.AuthenticationFailed('Invalid or expired device token.') from exc

        if expected_identifier != device_auth_token.device.device_identifier:
            raise exceptions.AuthenticationFailed('Device identifier does not match token owner.')

        # Keep device available in request.auth for compatibility with existing code.
        request._device_auth_token = device_auth_token
        return (AnonymousUser(), device_auth_token.device)

    def authenticate_header(self, request):
        return self.keyword


def default_device_auth_token_expiry(now):
    return now + timedelta(days=7)