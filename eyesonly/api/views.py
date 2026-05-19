import hashlib
import secrets
import base64
import binascii
import json
from pathlib import PurePosixPath
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.utils.dateparse import parse_datetime
from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.schemas.openapi import AutoSchema
from .schemas import (
    AddDeviceToGroupSchema,
    CreateGroupKeyEnvelopeSchema,
    CreateGroupSchema,
    DeleteEncryptedImageSchema,
    DeleteGroupSchema,
    DeregisterFCMDeviceSchema,
    NotifyGroupSchema,
    DeviceAuthChallengeSchema,
    DeviceAuthTokenSchema,
    DeviceAuthRevokeSchema,
    DeviceLeavesGroupSchema,
    DownloadEncryptedImageBlobSchema,
    GetDeviceGroupKeyEnvelopesSchema,
    HealthSchema,
    ListEncryptedImagesSchema,
    GetDeviceSelfStatusSchema,
    GetOwnGroupDevicesSchema,
    GetManagerGroupsSchema,
    ListGroupDevicesSchema,
    GetMainManagerGroupsSchema,
    GetDeviceGroupsSchema,
    RegisterDeviceSchema,
    RegisterFCMDeviceSchema,
    RemoveDeviceFromGroupSchema,
    UploadEncryptedImageSchema,
    UpdateGroupSchema,
)
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from eyesonly.api.permissions import IsGroupMainManager, IsGroupManager, IsGroupManagerOrDevice

from eyesonly.authentication.device_challenge_crypto import (
    encrypt_device_auth_challenge,
    generate_decoy_device_auth_challenge,
)
from eyesonly.authentication.device_authentication import (
    DeviceTokenAuthentication,
    default_device_auth_token_expiry,
)
from eyesonly.api.throttles import SettingsAwareScopedRateThrottle
from eyesonly.models import (
    Device,
    DeviceAuthChallenge,
    DeviceAuthToken,
    EncryptedImage,
    Organization,
    default_encrypted_image_expires_at,
    get_organization_name,
    Group,
    GroupDevices,
    GROUP_KEY_SCOPE_GROUP_SHARED,
    GROUP_KEY_SCOPE_MANAGER_ROSTER,
    GroupKeyEnvelope,
    ManagerRole,
    RecipientEnvelope,
    hash_device_auth_challenge,
)
from fcm_django.models import FCMDevice
import firebase_admin.messaging as messaging

from .serializers import (
    AddDeviceToGroupSerializer,
    CreateGroupKeyEnvelopeResponseSerializer,
    CreateGroupKeyEnvelopeSerializer,
    CreateGroupSerializer,
    DeleteGroupSerializer,
    RegisterFCMDeviceSerializer,
    DeviceLeavesGroupSerializer,
    DeviceAuthChallengeResponseSerializer,
    DeviceAuthChallengeRequestSerializer,
    DeviceAuthTokenResponseSerializer,
    DeviceAuthTokenRequestSerializer,
    DeviceEncryptedImageListResponseSerializer,
    DeviceRegistrationSerializer,
    DeviceGroupKeyEnvelopeSerializer,
    GroupDeviceSerializer,
    GetDeviceGroupKeyEnvelopesSerializer,
    GetDeviceSelfStatusSerializer,
    LogoutSerializer,
    ManagerGroupStatusSerializer,
    NotifyGroupSerializer,
    MainManagerGroupSerializer,
    RemoveDeviceFromGroupSerializer,
    UpdateGroupSerializer,
    UploadEncryptedImageResponseSerializer,
    UserGroupSerializer,
    UploadEncryptedImageSerializer,
)


def _get_organization_for_limits():
    """Return the tenant organization row used for limit enforcement."""
    return Organization.objects.order_by('id').first()


def _quota_exceeded_response(*, quota_name, current_count, maximum):
    return Response(
        {
            'detail': f"{quota_name} limit reached.",
            'quota': quota_name,
            'current': current_count,
            'maximum': maximum,
        },
        status=status.HTTP_403_FORBIDDEN,
    )


def _enforce_organization_quota(*, quota_name, maximum, current_count):
    if maximum is None:
        return None
    if current_count >= maximum:
        return _quota_exceeded_response(
            quota_name=quota_name,
            current_count=current_count,
            maximum=maximum,
        )
    return None




# we have to verify that the challenger owns the private key
class CreateDeviceAuthChallengeView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [SettingsAwareScopedRateThrottle]
    throttle_scope = 'device_auth_challenge'
    schema = DeviceAuthChallengeSchema()

    def post(self, request):
        serializer = DeviceAuthChallengeRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        device_identifier = serializer.validated_data['device_identifier']
        ttl_seconds = getattr(settings, 'DEVICE_AUTH_CHALLENGE_TTL_SECONDS', 300)

        now = timezone.now()
        challenge_ttl = timedelta(seconds=ttl_seconds)
        challenge_value = secrets.token_urlsafe(32)
        challenge_hash = hash_device_auth_challenge(challenge_value)
        expires_at = now + challenge_ttl

        with transaction.atomic():
            try:
                device = Device.objects.get(device_identifier=device_identifier)
            except Device.DoesNotExist:
                device = None

            if device is None:
                encrypted_challenge = generate_decoy_device_auth_challenge()
                #print("[Decoy Challenge] Returned a decoy device auth challenge (device not found)")
                return Response(
                    {
                        'encrypted_challenge': encrypted_challenge,
                        'expires_at': expires_at,
                    },
                    status=status.HTTP_201_CREATED,
                )

            try:
                encrypted_challenge = encrypt_device_auth_challenge(
                    challenge_value=challenge_value,
                    public_key=device.public_key,
                    public_key_algorithm=device.public_key_algorithm,
                )
            except ValueError:
                encrypted_challenge = generate_decoy_device_auth_challenge()
                #print("[Decoy Challenge] Returned a decoy device auth challenge (encryption error)")
                return Response(
                    {
                        'encrypted_challenge': encrypted_challenge,
                        'expires_at': expires_at,
                    },
                    status=status.HTTP_201_CREATED,
                )

            # expire any existing challenges for this device to prevent reuse, even if they haven't been used yet
            DeviceAuthChallenge.objects.filter(
                device=device,
                is_used=False,
                expires_at__gt=now,
            ).update(expires_at=now)

            challenge = DeviceAuthChallenge.objects.create(
                device=device,
                challenge_hash=challenge_hash,
                expires_at=expires_at,
            )
        return Response(
            {
                'encrypted_challenge': encrypted_challenge,
                'expires_at': challenge.expires_at,
            },
            status=status.HTTP_201_CREATED,
        )


class CreateDeviceAuthTokenView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [SettingsAwareScopedRateThrottle]
    throttle_scope = 'device_auth_token'
    schema = DeviceAuthTokenSchema()

    def post(self, request):
        serializer = DeviceAuthTokenRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        device_identifier = serializer.validated_data['device_identifier']
        challenge_value = serializer.validated_data['challenge']
        challenge_hash = hash_device_auth_challenge(challenge_value)
        now = timezone.now()

        with transaction.atomic():
            # Join through device__device_identifier so both "unknown device" and
            # "wrong challenge" paths execute the same number of DB queries, preventing
            # timing-based device enumeration.
            consumed_count = DeviceAuthChallenge.objects.filter(
                device__device_identifier=device_identifier,
                challenge_hash=challenge_hash,
                is_used=False,
                expires_at__gt=now,
            ).update(is_used=True)

            if consumed_count != 1:
                return Response({'detail': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

            device = Device.objects.get(device_identifier=device_identifier)

            raw_token = secrets.token_urlsafe(48)
            token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()

            token_ttl_days = getattr(settings, 'DEVICE_AUTH_TOKEN_TTL_DAYS', None)
            expires_at = (
                now + timedelta(days=token_ttl_days)
                if token_ttl_days is not None
                else default_device_auth_token_expiry(now)
            )

            auth_token = DeviceAuthToken.objects.create(
                device=device,
                token_hash=token_hash,
                expires_at=expires_at,
            )

        return Response(
            {
                'access_token': raw_token,
                'token_type': 'Bearer',
                'expires_at': auth_token.expires_at,
            },
            status=status.HTTP_201_CREATED,
        )


# dvice equivlent for log out
class RevokeDeviceAuthTokenView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    schema = DeviceAuthRevokeSchema()

    def post(self, request):
        device_auth_token = getattr(request, '_device_auth_token', None)
        if device_auth_token is None:
            return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)

        if not device_auth_token.is_revoked:
            device_auth_token.is_revoked = True
            device_auth_token.save(update_fields=['is_revoked'])

        return Response(status=status.HTTP_204_NO_CONTENT)


# only django staff accounts can register device identities.
# a staff user can create, update and delete groups via api client
class RegisterDeviceView(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = DeviceRegistrationSerializer
    schema = RegisterDeviceSchema()

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        device_identifier = serializer.validated_data['device_identifier']
        public_key = serializer.validated_data['public_key']
        public_key_algorithm = serializer.validated_data['public_key_algorithm']
        owner_user_provided = 'owner_user' in serializer.validated_data
        owner_user = serializer.validated_data.get('owner_user')

        organization = _get_organization_for_limits()

        with transaction.atomic():
            if not Device.objects.filter(device_identifier=device_identifier).exists():
                quota_error = _enforce_organization_quota(
                    quota_name='max_devices',
                    maximum=getattr(organization, 'max_devices', None),
                    current_count=Device.objects.count(),
                )
                if quota_error is not None:
                    return quota_error

            device, device_created = Device.objects.get_or_create(
                device_identifier=device_identifier,
                defaults={
                    'owner_user': owner_user,
                    'public_key': public_key,
                    'public_key_algorithm': public_key_algorithm,
                },
            )

            if not device_created:
                if (
                    owner_user_provided
                    and device.owner_user is not None
                    and device.owner_user != owner_user
                ):
                    return Response(
                        {'owner_user': ['This device is already assigned to a different owner.']},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                updated = False
                changes = {}
                if owner_user_provided and device.owner_user is None and owner_user is not None:
                    changes['owner_user'] = (device.owner_user_id, getattr(owner_user, 'id', None))
                    device.owner_user = owner_user
                    updated = True
                if device.public_key != public_key:
                    changes['public_key'] = (device.public_key, public_key)
                    device.public_key = public_key
                    updated = True
                if device.public_key_algorithm != public_key_algorithm:
                    changes['public_key_algorithm'] = (device.public_key_algorithm, public_key_algorithm)
                    device.public_key_algorithm = public_key_algorithm
                    updated = True
                if updated:
                    device.save(update_fields=list(changes.keys()))
                    # Optionally: log the update for audit
                    #print(f"[Device Key Update] Device {device_identifier} updated fields: {changes}")

        response_status = status.HTTP_201_CREATED if device_created else status.HTTP_200_OK
        return Response(
            {
                'device_identifier': device.device_identifier,
                'public_key_algorithm': device.public_key_algorithm,
                'device_created': device_created,
            },
            status=response_status,
        )


class CreateGroupView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]
    serializer_class = CreateGroupSerializer
    schema = CreateGroupSchema()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        organization = _get_organization_for_limits()

        with transaction.atomic():
            quota_error = _enforce_organization_quota(
                quota_name='max_groups',
                maximum=getattr(organization, 'max_groups', None),
                current_count=Group.objects.count(),
            )
            if quota_error is not None:
                return quota_error

            group = Group.objects.create(
                encrypted_name=serializer.validated_data['encrypted_name'],
                crypto_version=serializer.validated_data['crypto_version'],
                encryption_algorithm=serializer.validated_data['encryption_algorithm'],
                name_nonce=serializer.validated_data['name_nonce_bytes'],
            )
            ManagerRole.objects.create(manager=request.user, group=group, role='main_manager')

            owned_devices = Device.objects.filter(owner_user=request.user).only('id')
            GroupDevices.objects.bulk_create(
                [GroupDevices(group=group, device=device) for device in owned_devices],
            )

        response_serializer = MainManagerGroupSerializer(group, context={'request': request})
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class CreateGroupKeyEnvelopeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsGroupMainManager]
    serializer_class = CreateGroupKeyEnvelopeSerializer
    response_serializer_class = CreateGroupKeyEnvelopeResponseSerializer
    schema = CreateGroupKeyEnvelopeSchema()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        group = serializer.validated_data['group_obj']
        scope = serializer.validated_data['scope']
        key_envelopes = serializer.validated_data['key_envelopes']

        recipient_ids = [item['recipient_device_identifier'] for item in key_envelopes]
        group_device_links = GroupDevices.objects.select_related('device').filter(
            group=group,
            device__device_identifier__in=recipient_ids,
        )
        links_by_identifier = {
            link.device.device_identifier: link
            for link in group_device_links
        }

        missing_recipient_ids = sorted(
            recipient_id
            for recipient_id in recipient_ids
            if recipient_id not in links_by_identifier
        )
        if missing_recipient_ids:
            return Response(
                {
                    'key_envelopes': (
                        'Recipient devices must belong to the target group. Unknown recipients: '
                        + ', '.join(missing_recipient_ids)
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        if scope == GROUP_KEY_SCOPE_MANAGER_ROSTER:
            manager_user_ids = set(
                ManagerRole.objects.filter(
                    group=group,
                    role__in=('main_manager', 'manager'),
                ).values_list('manager_id', flat=True),
            )
            invalid_recipient_ids = sorted(
                recipient_id
                for recipient_id, link in links_by_identifier.items()
                if link.device.owner_user_id not in manager_user_ids
            )
            if invalid_recipient_ids:
                return Response(
                    {
                        'key_envelopes': (
                            'Manager roster envelopes may only target devices owned by a manager of '
                            'the target group. Invalid recipients: ' + ', '.join(invalid_recipient_ids)
                        ),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        envelope_rows = []
        for envelope in key_envelopes:
            recipient_device = links_by_identifier[envelope['recipient_device_identifier']].device
            if envelope['recipient_key_fingerprint'] != recipient_device.public_key_fingerprint:
                return Response(
                    {
                        'key_envelopes': (
                            f"Fingerprint mismatch for recipient '{recipient_device.device_identifier}'."
                        ),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                encrypted_group_key_bytes = base64.b64decode(
                    envelope['encrypted_group_key'],
                    validate=True,
                )
            except (binascii.Error, ValueError):
                return Response(
                    {'key_envelopes': 'encrypted_group_key must be valid base64.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            envelope_rows.append(
                {
                    'recipient_device': recipient_device,
                    'key_wrap_algorithm': envelope['key_wrap_algorithm'],
                    'recipient_key_fingerprint': envelope['recipient_key_fingerprint'],
                    'encrypted_group_key': encrypted_group_key_bytes,
                },
            )

        created_count = 0
        with transaction.atomic():
            for row in envelope_rows:
                _, created = GroupKeyEnvelope.objects.update_or_create(
                    group=group,
                    recipient_device=row['recipient_device'],
                    scope=scope,
                    defaults={
                        'key_wrap_algorithm': row['key_wrap_algorithm'],
                        'recipient_key_fingerprint': row['recipient_key_fingerprint'],
                        'encrypted_group_key': row['encrypted_group_key'],
                    },
                )
                if created:
                    created_count += 1

        response_serializer = self.response_serializer_class(
            {
                'group': group.uuid,
                'scope': scope,
                'envelope_count': len(envelope_rows),
                'created_count': created_count,
            },
        )
        response_status = status.HTTP_201_CREATED if created_count == len(envelope_rows) else status.HTTP_200_OK
        return Response(response_serializer.data, status=response_status)


class UpdateGroupView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsGroupMainManager]
    serializer_class = UpdateGroupSerializer
    schema = UpdateGroupSchema()

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        group = serializer.validated_data['group_obj']
        update_fields = []
        for field in ('encrypted_name', 'crypto_version', 'encryption_algorithm'):
            if field in serializer.validated_data:
                setattr(group, field, serializer.validated_data[field])
                update_fields.append(field)

        if 'name_nonce_bytes' in serializer.validated_data:
            group.name_nonce = serializer.validated_data['name_nonce_bytes']
            update_fields.append('name_nonce')

        group.save(update_fields=update_fields)

        response_serializer = MainManagerGroupSerializer(group, context={'request': request})
        return Response(response_serializer.data, status=status.HTTP_200_OK)


class DeleteGroupView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsGroupMainManager]
    serializer_class = DeleteGroupSerializer
    schema = DeleteGroupSchema()

    def delete(self, request):
        serializer_data = request.data if request.data else request.query_params
        serializer = self.serializer_class(data=serializer_data)
        serializer.is_valid(raise_exception=True)

        group = serializer.validated_data['group_obj']
        group.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class GetMainManagerGroupsView(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = MainManagerGroupSerializer
    schema = GetMainManagerGroupsSchema()

    def get(self, request):
        group_roles = ManagerRole.objects.filter(manager=request.user, role='main_manager')
        main_manager_groups = [gr.group for gr in group_roles]
        serializer = self.serializer_class(
            main_manager_groups,
            many=True,
            context={'request': request}
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetManagerGroupsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = ManagerGroupStatusSerializer
    schema = GetManagerGroupsSchema()

    def get(self, request):
        manager_roles = ManagerRole.objects.select_related('group').filter(
            manager=request.user,
        ).order_by('group__id')
        serializer = self.serializer_class(manager_roles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetOwnGroupDevicesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = GroupDeviceSerializer
    schema = GetOwnGroupDevicesSchema()

    def get(self, request):
        group_uuid = request.query_params.get('group')

        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

        group_devices = GroupDevices.objects.select_related('device').filter(
            group=group,
            device__owner_user=request.user,
        ).order_by('id')
        serializer = self.serializer_class(group_devices, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ListGroupDevicesView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsGroupManager]
    serializer_class = GroupDeviceSerializer
    schema = ListGroupDevicesSchema()

    def get(self, request):
        group_uuid = request.query_params.get('group')

        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

        group_devices = GroupDevices.objects.select_related('device').filter(group=group).order_by('id')
        serializer = self.serializer_class(group_devices, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



# only main managers can add already-registered devices to groups they manage.
class AddDeviceToGroupView(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsGroupMainManager]
    serializer_class = AddDeviceToGroupSerializer
    schema = AddDeviceToGroupSchema()

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        device_identifier = serializer.validated_data['device_identifier']
        group_uuid = serializer.validated_data['group']
        encrypted_member_name = serializer.validated_data['encrypted_member_name']
        is_manager = serializer.validated_data['is_manager']

        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            device = Device.objects.get(device_identifier=device_identifier)
        except Device.DoesNotExist:
            return Response({'detail': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

        with transaction.atomic():
            group_device, group_link_created = GroupDevices.objects.update_or_create(
                group=group,
                device=device,
                defaults={'encrypted_member_name': encrypted_member_name},
            )

            if is_manager:
                if device.owner_user is None:
                    return Response(
                        {'is_manager': ['Manager devices must have a registered owner_user.']},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                ManagerRole.objects.get_or_create(
                    manager=device.owner_user,
                    group=group,
                    defaults={'role': 'manager'},
                )

        response_status = status.HTTP_201_CREATED if group_link_created else status.HTTP_200_OK
        return Response(
            {
                'device_identifier': device.device_identifier,
                'group': str(group.uuid),
                'encrypted_member_name': group_device.encrypted_member_name,
                'group_link_created': group_link_created,
            },
            status=response_status,
        )

class RemoveDeviceFromGroupView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsGroupMainManager]
    serializer_class = RemoveDeviceFromGroupSerializer
    schema = RemoveDeviceFromGroupSchema()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        device_identifier = serializer.validated_data['device_identifier']
        group_uuid = serializer.validated_data['group']

        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Look up the device
        try:
            device = Device.objects.get(device_identifier=device_identifier)
        except Device.DoesNotExist:
            return Response({'detail': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Try to remove GroupDevices link
        try:
            group_device_link = GroupDevices.objects.get(group=group, device=device)
        except GroupDevices.DoesNotExist:
            # Device not in this group; return 404
            return Response(
                {'detail': 'Device is not part of this group.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        with transaction.atomic():
            group_device_link.delete()
            if device.owner_user is not None:
                remaining = GroupDevices.objects.filter(
                    group=group,
                    device__owner_user=device.owner_user,
                ).exclude(device=device).exists()
                if not remaining:
                    ManagerRole.objects.filter(
                        manager=device.owner_user,
                        group=group,
                        role='manager',
                    ).delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


class DeviceLeavesGroupView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    serializer_class = DeviceLeavesGroupSerializer
    schema = DeviceLeavesGroupSchema()

    def post(self, request):
        device_actor = getattr(request, 'auth', None)
        if device_actor is None:
            return Response(
                {'detail': 'Authentication credentials were not provided.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        group_uuid = serializer.validated_data['group']

        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

        try:
            group_device_link = GroupDevices.objects.get(group=group, device=device_actor)
        except GroupDevices.DoesNotExist:
            return Response(
                {'detail': 'Device is not part of this group.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        with transaction.atomic():
            group_device_link.delete()
            if device_actor.owner_user is not None:
                remaining = GroupDevices.objects.filter(
                    group=group,
                    device__owner_user=device_actor.owner_user,
                ).exclude(device=device_actor).exists()
                if not remaining:
                    ManagerRole.objects.filter(
                        manager=device_actor.owner_user,
                        group=group,
                        role='manager',
                    ).delete()

        return Response(status=status.HTTP_204_NO_CONTENT)


class GetDeviceGroupKeyEnvelopesView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    serializer_class = GetDeviceGroupKeyEnvelopesSerializer
    response_serializer_class = DeviceGroupKeyEnvelopeSerializer
    schema = GetDeviceGroupKeyEnvelopesSchema()

    def post(self, request):
        device_actor = getattr(request, 'auth', None)
        if device_actor is None:
            return Response(
                {'detail': 'Authentication credentials were not provided.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        requested_groups = serializer.validated_data['groups']
        requested_scopes = serializer.validated_data.get('scopes')

        allowed_query = Q(scope=GROUP_KEY_SCOPE_GROUP_SHARED)
        if device_actor.owner_user_id is not None:
            manager_group_ids = list(
                ManagerRole.objects.filter(
                    manager_id=device_actor.owner_user_id,
                    role__in=('main_manager', 'manager'),
                    group__uuid__in=requested_groups,
                ).values_list('group_id', flat=True),
            )
            if manager_group_ids:
                allowed_query |= Q(
                    scope=GROUP_KEY_SCOPE_MANAGER_ROSTER,
                    group_id__in=manager_group_ids,
                )

        envelopes = GroupKeyEnvelope.objects.filter(
            recipient_device=device_actor,
            group__uuid__in=requested_groups,
        ).filter(allowed_query)

        if requested_scopes:
            envelopes = envelopes.filter(scope__in=requested_scopes)

        envelopes = envelopes.select_related('group').order_by('group__id', 'scope')

        response_serializer = self.response_serializer_class(envelopes, many=True)
        return Response(response_serializer.data, status=status.HTTP_200_OK)



# all managers can upload images for their groups
class UploadEncryptedImageView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsGroupManager]
    serializer_class = UploadEncryptedImageSerializer
    response_serializer_class = UploadEncryptedImageResponseSerializer
    schema = UploadEncryptedImageSchema()

    def post(self, request):
        serializer_data = dict(request.data.items())
        raw_recipient_envelopes = serializer_data.get('recipient_envelopes')
        if isinstance(raw_recipient_envelopes, str):
            try:
                serializer_data['recipient_envelopes'] = json.loads(raw_recipient_envelopes)
            except json.JSONDecodeError:
                # Let serializer return a validation error for invalid shape/type.
                pass

        serializer = self.serializer_class(data=serializer_data)
        serializer.is_valid(raise_exception=True)
        
        group = serializer.validated_data['group_obj']

        encrypted_blob = serializer.validated_data['encrypted_blob']
        encrypted_caption = serializer.validated_data.get('encrypted_caption') or None
        crypto_version = serializer.validated_data['crypto_version']
        encryption_algorithm = serializer.validated_data['encryption_algorithm']
        payload_nonce_b64 = serializer.validated_data['payload_nonce']
        recipient_envelopes = serializer.validated_data['recipient_envelopes']
        expires_at = serializer.validated_data.get('expires_at') or default_encrypted_image_expires_at()
        client_hash = serializer.validated_data.get('client_ciphertext_hash_sha256')

        recipient_ids = [item['recipient_device_identifier'] for item in recipient_envelopes]
        group_device_links = GroupDevices.objects.select_related('device').filter(
            group=group,
            device__device_identifier__in=recipient_ids,
        )
        devices_by_identifier = {
            link.device.device_identifier: link.device
            for link in group_device_links
        }

        missing_recipient_ids = sorted(
            recipient_id
            for recipient_id in recipient_ids
            if recipient_id not in devices_by_identifier
        )
        if missing_recipient_ids:
            return Response(
                {
                    'recipient_envelopes': (
                        'Recipient devices must belong to the target group. Unknown recipients: '
                        + ', '.join(missing_recipient_ids)
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        envelope_rows = []
        for envelope in recipient_envelopes:
            recipient_device = devices_by_identifier[envelope['recipient_device_identifier']]
            if envelope['recipient_key_fingerprint'] != recipient_device.public_key_fingerprint:
                return Response(
                    {
                        'recipient_envelopes': (
                            f"Fingerprint mismatch for recipient '{recipient_device.device_identifier}'."
                        ),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                encrypted_content_key_bytes = base64.b64decode(
                    envelope['encrypted_content_key'],
                    validate=True,
                )
            except (binascii.Error, ValueError):
                return Response(
                    {'recipient_envelopes': 'encrypted_content_key must be valid base64.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            envelope_rows.append(
                {
                    'recipient_device': recipient_device,
                    'key_wrap_algorithm': envelope['key_wrap_algorithm'],
                    'recipient_key_fingerprint': envelope['recipient_key_fingerprint'],
                    'encrypted_content_key': encrypted_content_key_bytes,
                },
            )

        payload_nonce = base64.b64decode(payload_nonce_b64, validate=True)

        encrypted_blob.seek(0)
        hasher = hashlib.sha256()
        for chunk in encrypted_blob.chunks():
            hasher.update(chunk)
        ciphertext_hash = hasher.hexdigest()
        encrypted_blob.seek(0)

        if client_hash and client_hash != ciphertext_hash:
            return Response(
                {'client_ciphertext_hash_sha256': 'Does not match uploaded blob hash.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        organization = _get_organization_for_limits()

        with transaction.atomic():
            quota_error = _enforce_organization_quota(
                quota_name='max_images',
                maximum=getattr(organization, 'max_images', None),
                current_count=EncryptedImage.objects.count(),
            )
            if quota_error is not None:
                return quota_error

            encrypted_image = EncryptedImage.objects.create(
                encrypted_blob=encrypted_blob,
                encrypted_caption=encrypted_caption,
                group=group,
                uploaded_by=request.user,
                crypto_version=crypto_version,
                encryption_algorithm=encryption_algorithm,
                payload_nonce=payload_nonce,
                ciphertext_hash_sha256=ciphertext_hash,
                expires_at=expires_at,
            )

            RecipientEnvelope.objects.bulk_create(
                [
                    RecipientEnvelope(
                        encrypted_image=encrypted_image,
                        recipient_device=row['recipient_device'],
                        key_wrap_algorithm=row['key_wrap_algorithm'],
                        recipient_key_fingerprint=row['recipient_key_fingerprint'],
                        encrypted_content_key=row['encrypted_content_key'],
                    )
                    for row in envelope_rows
                ],
            )

        response_serializer = self.response_serializer_class(
            {
                'image_id': encrypted_image.id,
                'encrypted_caption': encrypted_image.encrypted_caption,
                'group': group.uuid,
                'recipient_count': len(envelope_rows),
                'ciphertext_hash_sha256': encrypted_image.ciphertext_hash_sha256,
                'created_at': encrypted_image.created_at,
                'expires_at': encrypted_image.expires_at,
            },
        )
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

# main_managers, managers and devices can delete images, but only for their groups
class DeleteEncryptedImageView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [IsGroupManagerOrDevice]
    schema = DeleteEncryptedImageSchema()

    def _get_device_encrypted_image(self, *, device_actor, group, image_uuid):
        try:
            recipient_envelope = RecipientEnvelope.objects.select_related('encrypted_image').get(
                recipient_device=device_actor,
                encrypted_image__uuid=image_uuid,
                encrypted_image__group=group,
            )
        except RecipientEnvelope.DoesNotExist:
            return None
        return recipient_envelope.encrypted_image

    def _extract_delete_params(self, request):
        group_uuid = request.data.get('group') if hasattr(request, 'data') else None
        image_uuid = request.data.get('image_uuid') if hasattr(request, 'data') else None

        if not group_uuid:
            group_uuid = request.query_params.get('group')
        if image_uuid is None:
            image_uuid = request.query_params.get('image_uuid')

        return group_uuid, image_uuid

    def _delete_image(self, request):
        group_uuid, image_uuid = self._extract_delete_params(request)

        if not group_uuid:
            return Response({'group': 'This field is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if image_uuid is None:
            return Response({'image_uuid': 'This field is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            return Response({'detail': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)

        device_actor = getattr(request, 'auth', None)
        if device_actor is not None:
            encrypted_image = self._get_device_encrypted_image(
                device_actor=device_actor,
                group=group,
                image_uuid=image_uuid,
            )
            if encrypted_image is None:
                return Response({'detail': 'Encrypted image not found.'}, status=status.HTTP_404_NOT_FOUND)
            encrypted_image.delete(deleted_by_device=device_actor)
        else:
            try:
                encrypted_image = EncryptedImage.objects.get(uuid=image_uuid, group=group)
            except EncryptedImage.DoesNotExist:
                return Response({'detail': 'Encrypted image not found.'}, status=status.HTTP_404_NOT_FOUND)
            encrypted_image.delete(deleted_by_user=request.user)

        return Response(status=status.HTTP_204_NO_CONTENT)

    def post(self, request):
        return self._delete_image(request)

    def delete(self, request):
        return self._delete_image(request)


# fetch images by device, group by group and date, endless pagination
class ListEncryptedImagesView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    response_serializer_class = DeviceEncryptedImageListResponseSerializer
    schema = ListEncryptedImagesSchema()

    default_page_size = 50
    max_page_size = 100

    def _get_device_actor(self, request):
        device_actor = getattr(request, 'auth', None)
        if device_actor is None:
            return None, Response(
                {'detail': 'Authentication credentials were not provided.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        return device_actor, None

    def _get_page_size(self, request):
        raw_limit = request.query_params.get('limit')
        if raw_limit in (None, ''):
            return self.default_page_size, None

        try:
            limit = int(raw_limit)
        except (TypeError, ValueError):
            return None, Response({'limit': 'A valid integer is required.'}, status=status.HTTP_400_BAD_REQUEST)

        if limit < 1 or limit > self.max_page_size:
            return None, Response(
                {'limit': f'Ensure this value is between 1 and {self.max_page_size}.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return limit, None

    def _encode_cursor(self, envelope):
        payload = json.dumps(
            {
                'group_id': envelope.encrypted_image.group_id,
                'created_at': envelope.encrypted_image.created_at.isoformat(),
                'image_id': envelope.encrypted_image_id,
            },
            separators=(',', ':'),
        ).encode('utf-8')
        return base64.urlsafe_b64encode(payload).decode('ascii')

    def _decode_cursor(self, cursor):
        try:
            payload = base64.urlsafe_b64decode(cursor.encode('ascii')).decode('utf-8')
            data = json.loads(payload)
            group_id = int(data['group_id'])
            created_at = parse_datetime(data['created_at'])
            image_id = int(data['image_id'])
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, binascii.Error):
            return None, Response({'cursor': 'Invalid cursor.'}, status=status.HTTP_400_BAD_REQUEST)

        if created_at is None:
            return None, Response({'cursor': 'Invalid cursor.'}, status=status.HTTP_400_BAD_REQUEST)
        return (group_id, created_at, image_id), None

    def _group_envelopes(self, envelopes):
        grouped_response = []
        current_group = None
        current_day_group = None

        for envelope in envelopes:
            encrypted_image = envelope.encrypted_image
            image_day = encrypted_image.created_at.date().isoformat()
            group_uuid = str(encrypted_image.group.uuid)

            if current_group is None or current_group['group'] != group_uuid:
                current_group = {
                    'group': group_uuid,
                    'encrypted_name': encrypted_image.group.encrypted_name,
                    'days': [],
                }
                grouped_response.append(current_group)
                current_day_group = None

            if current_day_group is None or current_day_group['day'] != image_day:
                current_day_group = {
                    'day': image_day,
                    'images': [],
                }
                current_group['days'].append(current_day_group)

            current_day_group['images'].append(envelope)

        return grouped_response

    def get(self, request):
        device_actor, error_response = self._get_device_actor(request)
        if error_response is not None:
            return error_response

        page_size, error_response = self._get_page_size(request)
        if error_response is not None:
            return error_response

        queryset = RecipientEnvelope.objects.filter(
            recipient_device=device_actor,
        ).select_related('encrypted_image', 'encrypted_image__group').order_by(
            'encrypted_image__group_id',
            '-encrypted_image__created_at',
            '-encrypted_image_id',
        )

        raw_cursor = request.query_params.get('cursor')
        if raw_cursor:
            cursor_values, error_response = self._decode_cursor(raw_cursor)
            if error_response is not None:
                return error_response

            cursor_group_id, cursor_created_at, cursor_image_id = cursor_values
            queryset = queryset.filter(
                Q(encrypted_image__group_id__gt=cursor_group_id)
                | Q(
                    encrypted_image__group_id=cursor_group_id,
                    encrypted_image__created_at__lt=cursor_created_at,
                )
                | Q(
                    encrypted_image__group_id=cursor_group_id,
                    encrypted_image__created_at=cursor_created_at,
                    encrypted_image_id__lt=cursor_image_id,
                ),
            )

        envelopes = list(queryset[: page_size + 1])
        has_next_page = len(envelopes) > page_size
        page_envelopes = envelopes[:page_size]
        next_cursor = self._encode_cursor(page_envelopes[-1]) if has_next_page and page_envelopes else None

        response_serializer = self.response_serializer_class(
            {
                'groups': self._group_envelopes(page_envelopes),
                'next_cursor': next_cursor,
            },
        )
        return Response(response_serializer.data, status=status.HTTP_200_OK)


class DownloadEncryptedImageBlobView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    schema = DownloadEncryptedImageBlobSchema()

    def _get_internal_redirect_path(self, blob_name):
        internal_prefix = getattr(
            settings,
            'ENCRYPTED_IMAGES_INTERNAL_LOCATION',
            '/internal-encrypted-images/',
        )
        normalized_prefix = f"/{str(internal_prefix).strip('/')}" if internal_prefix else '/internal-encrypted-images'
        normalized_blob_name = str(blob_name).replace('\\', '/').lstrip('/')
        path_parts = PurePosixPath(normalized_blob_name).parts
        if not normalized_blob_name or '..' in path_parts:
            return None
        return f'{normalized_prefix}/{normalized_blob_name}'

    def get(self, request, image_uuid):
        device_actor = getattr(request, 'auth', None)
        if device_actor is None:
            return Response(
                {'detail': 'Authentication credentials were not provided.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            recipient_envelope = RecipientEnvelope.objects.select_related('encrypted_image').get(
                recipient_device=device_actor,
                encrypted_image__uuid=image_uuid,
            )
        except RecipientEnvelope.DoesNotExist:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        encrypted_image = recipient_envelope.encrypted_image
        blob_name = encrypted_image.encrypted_blob.name
        internal_redirect_path = self._get_internal_redirect_path(blob_name)
        if internal_redirect_path is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        if not encrypted_image.encrypted_blob.storage.exists(blob_name):
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        response = HttpResponse(content_type='application/octet-stream')
        response['X-Accel-Redirect'] = internal_redirect_path
        response['Content-Disposition'] = f'attachment; filename="encrypted-image-{encrypted_image.uuid}.bin"'
        response['Cache-Control'] = 'private, no-store'
        return response

class HealthView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    schema = HealthSchema()

    def get(self, request):
        return Response(
            {'status': 'ok', 'organization': get_organization_name()},
            status=status.HTTP_200_OK,
        )


class LogoutView(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data['refresh']

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response({'detail': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(status=status.HTTP_204_NO_CONTENT)
    
class GetDeviceGroupsView(APIView):

    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    serializer_class = UserGroupSerializer
    schema = GetDeviceGroupsSchema()

    def get(self, request):
        device_actor = getattr(request, 'auth', None)
        if device_actor is None:
            return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)

        groups = Group.objects.filter(groupdevices__device=device_actor).distinct().order_by('id')
        serializer = UserGroupSerializer(groups, many=True, context={'request': request, 'device': device_actor})
        return Response(serializer.data, status=status.HTTP_200_OK)


class GetDeviceSelfStatusView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    serializer_class = GetDeviceSelfStatusSerializer
    schema = GetDeviceSelfStatusSchema()
    
    def get_serializer(self, *args, **kwargs):
        if self.serializer_class is None:
            return None
        return self.serializer_class(*args, **kwargs)

    def get(self, request):
        device_actor = getattr(request, 'auth', None)
        if device_actor is None:
            return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)

        group_names = list(
            Group.objects.filter(groupdevices__device=device_actor)
            .distinct()
            .order_by('encrypted_name')
            .values_list('encrypted_name', flat=True),
        )
        serializer = self.get_serializer(
            {
                'device_identifier': device_actor.device_identifier,
                'is_registered': True,
                'group_names': group_names,
                'organization_name': get_organization_name(),
            },
        )
        return Response(serializer.data, status=status.HTTP_200_OK)


class RegisterFCMDeviceView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    schema = RegisterFCMDeviceSchema()

    def post(self, request):
        device_actor = getattr(request, 'auth', None)
        if device_actor is None:
            return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = RegisterFCMDeviceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        registration_id = serializer.validated_data['registration_id']
        device_type = serializer.validated_data['type']

        existing = device_actor.fcm_device
        if existing is not None:
            existing.registration_id = registration_id
            existing.active = True
            existing.save(update_fields=['registration_id', 'active'])
            return Response(status=status.HTTP_200_OK)

        with transaction.atomic():
            fcm_device = FCMDevice.objects.create(
                registration_id=registration_id,
                type=device_type,
            )
            device_actor.fcm_device = fcm_device
            device_actor.save(update_fields=['fcm_device'])
        return Response(status=status.HTTP_201_CREATED)


class DeregisterFCMDeviceView(APIView):
    authentication_classes = [DeviceTokenAuthentication]
    permission_classes = [AllowAny]
    schema = DeregisterFCMDeviceSchema()

    def delete(self, request):
        device_actor = getattr(request, 'auth', None)
        if device_actor is None:
            return Response({'detail': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)

        fcm_device = device_actor.fcm_device
        if fcm_device is None:
            return Response({'detail': 'No FCM device registration found.'}, status=status.HTTP_404_NOT_FOUND)

        with transaction.atomic():
            device_actor.fcm_device = None
            device_actor.save(update_fields=['fcm_device'])
            fcm_device.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class NotifyGroupView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsGroupManager]
    schema = NotifyGroupSchema()

    _FCM_BATCH_SIZE = 500

    def post(self, request):
        serializer = NotifyGroupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        group = serializer.validated_data['group_obj']
        encrypted_payload = serializer.validated_data['encrypted_payload']
        nonce = serializer.validated_data['nonce']
        crypto_version = serializer.validated_data['crypto_version']
        encryption_algorithm = serializer.validated_data['encryption_algorithm']

        group_devices = GroupDevices.objects.select_related('device__fcm_device').filter(group=group)
        tokens = []
        skipped_count = 0
        for gd in group_devices:
            fcm = gd.device.fcm_device
            if fcm is not None and fcm.active:
                tokens.append(fcm.registration_id)
            else:
                skipped_count += 1

        if not tokens:
            return Response(
                {'notified_count': 0, 'skipped_count': skipped_count},
                status=status.HTTP_200_OK,
            )

        fcm_data = {
            'event': 'new_images',
            'group': str(group.uuid),
            'encrypted_payload': encrypted_payload,
            'nonce': nonce,
            'crypto_version': str(crypto_version),
            'encryption_algorithm': encryption_algorithm,
        }

        notified_count = 0
        for i in range(0, len(tokens), self._FCM_BATCH_SIZE):
            batch = tokens[i:i + self._FCM_BATCH_SIZE]
            message = messaging.MulticastMessage(
                tokens=batch,
                data=fcm_data,
                notification=messaging.Notification(
                    title='Eyes Only',
                    body='There are new images for you.',
                ),
                android=messaging.AndroidConfig(priority='high'),
                apns=messaging.APNSConfig(
                    headers={
                        'apns-priority': '10',
                        'apns-push-type': 'alert',
                    },
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            content_available=True,
                            mutable_content=True,
                        ),
                    ),
                ),
            )
            result = messaging.send_each_for_multicast(message)
            notified_count += result.success_count

        return Response(
            {'notified_count': notified_count, 'skipped_count': skipped_count},
            status=status.HTTP_200_OK,
        )

