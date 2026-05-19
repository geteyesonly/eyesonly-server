import base64
import binascii
import re

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers

from eyesonly.authentication.device_challenge_crypto import DEFAULT_KEY_WRAP_ALGORITHM
from eyesonly.models import (
    Device,
    Group,
    GroupDevices,
    GROUP_KEY_SCOPES,
    GROUP_KEY_SCOPE_GROUP_SHARED,
    ManagerRole,
)

User = get_user_model()



# Base serializer for group info
class GroupBaseSerializer(serializers.ModelSerializer):
    user_role = serializers.SerializerMethodField()
    name_nonce = serializers.SerializerMethodField()

    class Meta:
        model = Group
        fields = ('uuid', 'encrypted_name', 'crypto_version', 'encryption_algorithm', 'name_nonce', 'user_role')

    def get_name_nonce(self, obj):
        name_nonce = getattr(obj, 'name_nonce', None)
        if name_nonce is None:
            return None
        return base64.b64encode(bytes(name_nonce)).decode('ascii')

    def get_user_role(self, obj):
        raise NotImplementedError("Subclasses must implement get_user_role")

# Device-centric group serializer. Devices cannot be linked to users,
# so role resolution is not possible from device context.
class UserGroupSerializer(GroupBaseSerializer):
    def get_user_role(self, obj):
        return 'member'

# User-centric group serializer (uses request.user context)
class MainManagerGroupSerializer(GroupBaseSerializer):
    def get_user_role(self, obj):
        request = self.context.get('request')
        if not request or not hasattr(request, 'user') or not request.user.is_authenticated:
            return 'member'
        is_main_manager = ManagerRole.objects.filter(manager=request.user, group=obj, role='main_manager').exists()
        if is_main_manager:
            return 'main_manager'
        is_manager = ManagerRole.objects.filter(manager=request.user, group=obj, role='manager').exists()
        if is_manager:
            return 'manager'
        return 'member'


class ManagerGroupStatusSerializer(serializers.Serializer):
    uuid = serializers.UUIDField(source='group.uuid', read_only=True)
    encrypted_name = serializers.CharField(source='group.encrypted_name', read_only=True)
    crypto_version = serializers.IntegerField(source='group.crypto_version', read_only=True)
    encryption_algorithm = serializers.CharField(source='group.encryption_algorithm', read_only=True)
    name_nonce = serializers.SerializerMethodField(read_only=True)
    status = serializers.CharField(source='role', read_only=True)

    def get_name_nonce(self, obj):
        name_nonce = getattr(obj.group, 'name_nonce', None)
        if name_nonce is None:
            return None
        return base64.b64encode(bytes(name_nonce)).decode('ascii')


class GroupDeviceSerializer(serializers.ModelSerializer):
    device_identifier = serializers.CharField(source='device.device_identifier', read_only=True)
    encrypted_member_name = serializers.CharField(
        read_only=True,
        allow_null=True,
        help_text=(
            'Roster/admin metadata ciphertext for this device link. This should be encrypted '
            'client-side with the manager_roster group metadata key, not the group_shared key.'
        ),
    )
    public_key = serializers.CharField(source='device.public_key', read_only=True)
    public_key_algorithm = serializers.CharField(source='device.public_key_algorithm', read_only=True)
    public_key_fingerprint = serializers.CharField(source='device.public_key_fingerprint', read_only=True)

    class Meta:
        model = GroupDevices
        fields = (
            'device_identifier',
            'encrypted_member_name',
            'public_key',
            'public_key_algorithm',
            'public_key_fingerprint',
        )


class GroupPayloadSerializer(serializers.Serializer):
    encrypted_name = serializers.CharField()
    crypto_version = serializers.IntegerField(min_value=1, max_value=32767, default=1)
    encryption_algorithm = serializers.CharField(max_length=32, default='xchacha20poly1305')
    name_nonce = serializers.CharField()

    _NONCE_LENGTH_BY_ALGORITHM = {
        'xchacha20poly1305': 24,
    }

    def validate_encryption_algorithm(self, value):
        allowed_algorithms = tuple(
            getattr(settings, 'ALLOWED_IMAGE_ENCRYPTION_ALGORITHMS', ('xchacha20poly1305',)),
        )
        if value not in allowed_algorithms:
            raise serializers.ValidationError('Unsupported encryption_algorithm.')
        return value

    def validate_name_nonce(self, value):
        try:
            nonce = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise serializers.ValidationError('name_nonce must be valid base64.') from exc

        if not nonce:
            raise serializers.ValidationError('name_nonce cannot be empty.')

        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)

        algorithm = attrs.get('encryption_algorithm')
        name_nonce = attrs.get('name_nonce')
        if algorithm and name_nonce:
            expected_len = self._NONCE_LENGTH_BY_ALGORITHM.get(algorithm)
            if expected_len is not None:
                nonce = base64.b64decode(name_nonce, validate=True)
                if len(nonce) != expected_len:
                    raise serializers.ValidationError(
                        {
                            'name_nonce': (
                                f'Invalid nonce length for {algorithm}. '
                                f'Expected {expected_len} bytes.'
                            ),
                        },
                    )

        if name_nonce is not None:
            attrs['name_nonce_bytes'] = base64.b64decode(name_nonce, validate=True)
        return attrs


class CreateGroupSerializer(GroupPayloadSerializer):
    pass


class UpdateGroupSerializer(GroupPayloadSerializer):
    group = serializers.UUIDField()
    encrypted_name = serializers.CharField(required=False)
    crypto_version = serializers.IntegerField(min_value=1, max_value=32767, required=False)
    encryption_algorithm = serializers.CharField(max_length=32, required=False)
    name_nonce = serializers.CharField(required=False)

    def validate_group(self, value):
        try:
            self._group_obj = Group.objects.get(uuid=value)
        except Group.DoesNotExist as exc:
            raise serializers.ValidationError('Group not found.') from exc
        return value

    def validate(self, attrs):
        attrs['group_obj'] = getattr(self, '_group_obj', None)

        if 'name_nonce' in attrs and 'encryption_algorithm' not in attrs and attrs['group_obj'] is not None:
            attrs['encryption_algorithm'] = attrs['group_obj'].encryption_algorithm

        attrs = super().validate(attrs)
        attrs['group_obj'] = getattr(self, '_group_obj', None)

        updatable_fields = {'encrypted_name', 'crypto_version', 'encryption_algorithm', 'name_nonce'}
        if not any(field in attrs for field in updatable_fields):
            raise serializers.ValidationError('At least one updatable field must be provided.')

        return attrs


class DeleteGroupSerializer(serializers.Serializer):
    group = serializers.UUIDField()

    def validate_group(self, value):
        try:
            self._group_obj = Group.objects.get(uuid=value)
        except Group.DoesNotExist as exc:
            raise serializers.ValidationError('Group not found.') from exc
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        attrs['group_obj'] = getattr(self, '_group_obj', None)
        return attrs


class DeleteEncryptedImageSerializer(serializers.Serializer):
    group = serializers.UUIDField()
    image_uuid = serializers.UUIDField()


class DeviceAuthChallengeRequestSerializer(serializers.Serializer):
    device_identifier = serializers.CharField(max_length=255)


class DeviceAuthChallengeEnvelopeSerializer(serializers.Serializer):
    algorithm = serializers.CharField(max_length=64, read_only=True)
    ephemeral_public_key = serializers.CharField(read_only=True)
    nonce = serializers.CharField(read_only=True)
    ciphertext = serializers.CharField(read_only=True)


class DeviceAuthChallengeResponseSerializer(serializers.Serializer):
    encrypted_challenge = DeviceAuthChallengeEnvelopeSerializer(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True)


class DeviceAuthTokenRequestSerializer(serializers.Serializer):
    device_identifier = serializers.CharField(max_length=255)
    challenge = serializers.CharField(max_length=128)


class DeviceAuthTokenResponseSerializer(serializers.Serializer):
    access_token = serializers.CharField(read_only=True)
    token_type = serializers.CharField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

# the main manager scans a qr code on the device and registers it for the group, providing the device identifier, public key and public key algorithm.
# The device identifier is shown in the qr code and is also on the device itself, so the main manager can verify that they are registering the correct device.
# The main manager can only register devices for their own group.
class DeviceRegistrationSerializer(serializers.Serializer):
    device_identifier = serializers.CharField(max_length=255)
    public_key = serializers.CharField()
    public_key_algorithm = serializers.CharField(max_length=50)
    owner_user = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        required=False,
        allow_null=True,
    )

    def validate(self, attrs):
        attrs = super().validate(attrs)

        if 'owner_user' not in attrs:
            return attrs

        requested_owner = attrs.get('owner_user')
        existing_device = Device.objects.filter(
            device_identifier=attrs['device_identifier'],
        ).only('owner_user').first()

        if existing_device and existing_device.owner_user is not None:
            if requested_owner != existing_device.owner_user:
                raise serializers.ValidationError(
                    {'owner_user': 'This device is already assigned to a different owner.'},
                )
            return attrs

        request = self.context.get('request')
        if requested_owner is None or request is None or request.user.is_anonymous:
            return attrs

        if requested_owner != request.user:
            raise serializers.ValidationError('You may only assign yourself as the device owner.')

        return attrs


class AddDeviceToGroupSerializer(serializers.Serializer):
    device_identifier = serializers.CharField(max_length=255)
    group = serializers.UUIDField()
    encrypted_member_name = serializers.CharField(
        help_text=(
            'Roster/admin metadata ciphertext for this device in the group. Encrypt this with '
            'the manager_roster key scope so only manager-owned devices can decrypt it.'
        ),
    )
    is_manager = serializers.BooleanField(
        required=False,
        default=False,
        help_text=(
            'Set true to grant manager role in this group to the device owner. Requires '
            'the device to have a registered user.'
        ),
    )

    def validate(self, attrs):
        attrs = super().validate(attrs)

        if not attrs.get('is_manager'):
            return attrs

        device = Device.objects.filter(device_identifier=attrs['device_identifier']).only('owner_user').first()
        if device is not None and device.owner_user is None:
            raise serializers.ValidationError(
                {'is_manager': 'Manager devices must have a registered user.'},
            )

        return attrs


class AddDeviceToGroupResponseSerializer(serializers.Serializer):
    device_identifier = serializers.CharField(read_only=True)
    group = serializers.UUIDField(read_only=True)
    encrypted_member_name = serializers.CharField(
        read_only=True,
        allow_null=True,
        help_text=(
            'Roster/admin metadata ciphertext stored for this device link. This value belongs '
            'to the manager_roster key scope.'
        ),
    )
    group_link_created = serializers.BooleanField(read_only=True)


class RemoveDeviceFromGroupSerializer(serializers.Serializer):
    device_identifier = serializers.CharField(max_length=255)
    group = serializers.UUIDField()


class RemoveDeviceFromGroupResponseSerializer(serializers.Serializer):
    detail = serializers.CharField(read_only=True)


class DeviceLeavesGroupSerializer(serializers.Serializer):
    group = serializers.UUIDField()


class GetDeviceSelfStatusSerializer(serializers.Serializer):
    device_identifier = serializers.CharField(max_length=255, read_only=True)
    is_registered = serializers.BooleanField(read_only=True)
    group_names = serializers.ListField(
        child=serializers.CharField(max_length=255),
        read_only=True,
    )
    organization_name = serializers.SerializerMethodField(read_only=True)

    def get_organization_name(self, _obj):
        from eyesonly.models import get_organization_name
        return get_organization_name()


class RecipientEnvelopeSerializer(serializers.Serializer):
    recipient_device_identifier = serializers.CharField(max_length=255)
    key_wrap_algorithm = serializers.CharField(max_length=32, default=DEFAULT_KEY_WRAP_ALGORITHM)
    recipient_key_fingerprint = serializers.CharField(max_length=64)
    encrypted_content_key = serializers.CharField()

    def validate_key_wrap_algorithm(self, value):
        allowed_algorithms = tuple(
            getattr(
                settings,
                'ALLOWED_KEY_WRAP_ALGORITHMS',
                (DEFAULT_KEY_WRAP_ALGORITHM,),
            ),
        )
        if value not in allowed_algorithms:
            raise serializers.ValidationError('Unsupported key_wrap_algorithm.')
        return value

    def validate_recipient_key_fingerprint(self, value):
        if not re.fullmatch(r'[a-f0-9]{64}', value):
            raise serializers.ValidationError('recipient_key_fingerprint must be 64 lowercase hex characters.')
        return value

    def validate_encrypted_content_key(self, value):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise serializers.ValidationError('encrypted_content_key must be valid base64.') from exc

        if not decoded:
            raise serializers.ValidationError('encrypted_content_key cannot be empty.')

        max_bytes = int(getattr(settings, 'MAX_ENCRYPTED_CONTENT_KEY_BYTES', 2048))
        if len(decoded) > max_bytes:
            raise serializers.ValidationError('encrypted_content_key is too large.')

        return value


class GroupKeyEnvelopeSerializer(serializers.Serializer):
    recipient_device_identifier = serializers.CharField(max_length=255)
    key_wrap_algorithm = serializers.CharField(max_length=32, default=DEFAULT_KEY_WRAP_ALGORITHM)
    recipient_key_fingerprint = serializers.CharField(max_length=64)
    encrypted_group_key = serializers.CharField(
        help_text=(
            'Base64-encoded wrapped shared key material for the selected scope. Use group_shared '
            'for metadata all group devices may decrypt, and manager_roster for manager-only '
            'roster/admin metadata.'
        ),
    )

    def validate_key_wrap_algorithm(self, value):
        allowed_algorithms = tuple(
            getattr(
                settings,
                'ALLOWED_KEY_WRAP_ALGORITHMS',
                (DEFAULT_KEY_WRAP_ALGORITHM,),
            ),
        )
        if value not in allowed_algorithms:
            raise serializers.ValidationError('Unsupported key_wrap_algorithm.')
        return value

    def validate_recipient_key_fingerprint(self, value):
        if not re.fullmatch(r'[a-f0-9]{64}', value):
            raise serializers.ValidationError('recipient_key_fingerprint must be 64 lowercase hex characters.')
        return value

    def validate_encrypted_group_key(self, value):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise serializers.ValidationError('encrypted_group_key must be valid base64.') from exc

        if not decoded:
            raise serializers.ValidationError('encrypted_group_key cannot be empty.')

        max_bytes = int(getattr(settings, 'MAX_ENCRYPTED_CONTENT_KEY_BYTES', 2048))
        if len(decoded) > max_bytes:
            raise serializers.ValidationError('encrypted_group_key is too large.')

        return value


class CreateGroupKeyEnvelopeSerializer(serializers.Serializer):
    group = serializers.UUIDField()
    scope = serializers.ChoiceField(
        choices=GROUP_KEY_SCOPES,
        default=GROUP_KEY_SCOPE_GROUP_SHARED,
        help_text=(
            'Key scope for the wrapped group metadata key. Use group_shared for metadata any '
            'group device may decrypt. Use manager_roster for manager-only roster/admin metadata '
            'such as encrypted_member_name.'
        ),
    )
    key_envelopes = GroupKeyEnvelopeSerializer(many=True, allow_empty=False)

    def validate_group(self, value):
        try:
            self._group_obj = Group.objects.get(uuid=value)
        except Group.DoesNotExist as exc:
            raise serializers.ValidationError('Group not found.') from exc
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        attrs['group_obj'] = getattr(self, '_group_obj', None)

        key_envelopes = attrs.get('key_envelopes') or []
        recipient_ids = [item['recipient_device_identifier'] for item in key_envelopes]
        if len(recipient_ids) != len(set(recipient_ids)):
            raise serializers.ValidationError(
                {'key_envelopes': 'Duplicate recipient_device_identifier values are not allowed.'},
            )

        return attrs


class CreateGroupKeyEnvelopeResponseSerializer(serializers.Serializer):
    group = serializers.UUIDField(read_only=True)
    scope = serializers.ChoiceField(
        choices=GROUP_KEY_SCOPES,
        read_only=True,
        help_text='The key scope that was created or updated.',
    )
    envelope_count = serializers.IntegerField(read_only=True)
    created_count = serializers.IntegerField(read_only=True)


class GetDeviceGroupKeyEnvelopesSerializer(serializers.Serializer):
    groups = serializers.ListField(
        child=serializers.UUIDField(),
        allow_empty=False,
        help_text='Group UUIDs to fetch wrapped metadata keys for.',
    )
    scopes = serializers.ListField(
        child=serializers.ChoiceField(choices=GROUP_KEY_SCOPES),
        required=False,
        allow_empty=False,
        help_text=(
            'Optional scope filter. Omit to fetch all scopes available to the authenticated '
            'device. Manager-owned devices may receive both group_shared and manager_roster; '
            'regular devices receive only group_shared.'
        ),
    )

    def validate_groups(self, value):
        if len(value) != len(set(value)):
            raise serializers.ValidationError('Duplicate group UUID values are not allowed.')
        return value

    def validate_scopes(self, value):
        if len(value) != len(set(value)):
            raise serializers.ValidationError('Duplicate scope values are not allowed.')
        return value


class DeviceGroupKeyEnvelopeSerializer(serializers.Serializer):
    group = serializers.UUIDField(source='group.uuid', read_only=True)
    scope = serializers.CharField(
        read_only=True,
        help_text='Scope of the wrapped group metadata key: group_shared or manager_roster.',
    )
    key_wrap_algorithm = serializers.CharField(read_only=True)
    recipient_key_fingerprint = serializers.CharField(read_only=True)
    encrypted_group_key = serializers.SerializerMethodField()

    def get_encrypted_group_key(self, obj):
        encrypted_group_key = getattr(obj, 'encrypted_group_key', None)
        if encrypted_group_key is None:
            return None
        return base64.b64encode(bytes(encrypted_group_key)).decode('ascii')


class UploadEncryptedImageSerializer(serializers.Serializer):
    encrypted_blob = serializers.FileField()
    encrypted_caption = serializers.CharField(required=False, allow_blank=True)
    group = serializers.UUIDField()
    crypto_version = serializers.IntegerField(min_value=1, max_value=32767, default=1)
    encryption_algorithm = serializers.CharField(max_length=32, default='xchacha20poly1305')
    payload_nonce = serializers.CharField()
    recipient_envelopes = RecipientEnvelopeSerializer(many=True, allow_empty=False)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    client_ciphertext_hash_sha256 = serializers.CharField(max_length=64, required=False)

    _NONCE_LENGTH_BY_ALGORITHM = {
        'xchacha20poly1305': 24,
    }

    def validate_encryption_algorithm(self, value):
        allowed_algorithms = tuple(
            getattr(settings, 'ALLOWED_IMAGE_ENCRYPTION_ALGORITHMS', ('xchacha20poly1305',)),
        )
        if value not in allowed_algorithms:
            raise serializers.ValidationError('Unsupported encryption_algorithm.')
        return value

    def validate_client_ciphertext_hash_sha256(self, value):
        if not re.fullmatch(r'[a-f0-9]{64}', value):
            raise serializers.ValidationError('client_ciphertext_hash_sha256 must be 64 lowercase hex characters.')
        return value

    def validate_payload_nonce(self, value):
        try:
            nonce = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise serializers.ValidationError('payload_nonce must be valid base64.') from exc

        if not nonce:
            raise serializers.ValidationError('payload_nonce cannot be empty.')
        return value

    def validate_group(self, value):
        try:
            self._group_obj = Group.objects.get(uuid=value)
        except Group.DoesNotExist as exc:
            raise serializers.ValidationError('Group not found.') from exc
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        attrs['group_obj'] = getattr(self, '_group_obj', None)

        algorithm = attrs.get('encryption_algorithm')
        payload_nonce = attrs.get('payload_nonce')
        if algorithm and payload_nonce:
            expected_len = self._NONCE_LENGTH_BY_ALGORITHM.get(algorithm)
            if expected_len is not None:
                nonce = base64.b64decode(payload_nonce, validate=True)
                if len(nonce) != expected_len:
                    raise serializers.ValidationError(
                        {
                            'payload_nonce': (
                                f'Invalid nonce length for {algorithm}. '
                                f'Expected {expected_len} bytes.'
                            ),
                        },
                    )

        recipient_envelopes = attrs.get('recipient_envelopes') or []
        recipient_ids = [item['recipient_device_identifier'] for item in recipient_envelopes]
        if len(recipient_ids) != len(set(recipient_ids)):
            raise serializers.ValidationError(
                {'recipient_envelopes': 'Duplicate recipient_device_identifier values are not allowed.'},
            )

        expires_at = attrs.get('expires_at')
        if expires_at is not None and expires_at <= timezone.now():
            raise serializers.ValidationError({'expires_at': 'expires_at must be in the future.'})

        return attrs


class UploadEncryptedImageResponseSerializer(serializers.Serializer):
    image_id = serializers.IntegerField(read_only=True)
    encrypted_caption = serializers.CharField(read_only=True, allow_null=True)
    group = serializers.UUIDField(read_only=True)
    recipient_count = serializers.IntegerField(read_only=True)
    ciphertext_hash_sha256 = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True, allow_null=True)


class DeviceEncryptedImageItemSerializer(serializers.Serializer):
    image_uuid = serializers.UUIDField(source='encrypted_image.uuid', read_only=True)
    encrypted_caption = serializers.CharField(source='encrypted_image.encrypted_caption', read_only=True, allow_null=True)
    crypto_version = serializers.IntegerField(source='encrypted_image.crypto_version', read_only=True)
    encryption_algorithm = serializers.CharField(source='encrypted_image.encryption_algorithm', read_only=True)
    payload_nonce = serializers.SerializerMethodField(read_only=True)
    ciphertext_hash_sha256 = serializers.CharField(source='encrypted_image.ciphertext_hash_sha256', read_only=True)
    key_wrap_algorithm = serializers.CharField(read_only=True)
    recipient_key_fingerprint = serializers.CharField(read_only=True)
    encrypted_content_key = serializers.SerializerMethodField(read_only=True)
    created_at = serializers.DateTimeField(source='encrypted_image.created_at', read_only=True)
    expires_at = serializers.DateTimeField(source='encrypted_image.expires_at', read_only=True, allow_null=True)

    def get_payload_nonce(self, obj):
        payload_nonce = getattr(obj.encrypted_image, 'payload_nonce', None)
        if payload_nonce is None:
            return None
        return base64.b64encode(bytes(payload_nonce)).decode('ascii')

    def get_encrypted_content_key(self, obj):
        encrypted_content_key = getattr(obj, 'encrypted_content_key', None)
        if encrypted_content_key is None:
            return None
        return base64.b64encode(bytes(encrypted_content_key)).decode('ascii')


class DeviceEncryptedImageDayGroupSerializer(serializers.Serializer):
    day = serializers.DateField(read_only=True)
    images = DeviceEncryptedImageItemSerializer(many=True, read_only=True)


class DeviceEncryptedImageGroupSerializer(serializers.Serializer):
    group = serializers.UUIDField(read_only=True)
    encrypted_name = serializers.CharField(read_only=True)
    days = DeviceEncryptedImageDayGroupSerializer(many=True, read_only=True)


class DeviceEncryptedImageListResponseSerializer(serializers.Serializer):
    groups = DeviceEncryptedImageGroupSerializer(many=True, read_only=True)
    next_cursor = serializers.CharField(read_only=True, allow_null=True)


class RegisterFCMDeviceSerializer(serializers.Serializer):
    registration_id = serializers.CharField()
    type = serializers.ChoiceField(choices=['android', 'ios', 'web'])


class NotifyGroupSerializer(serializers.Serializer):
    group = serializers.UUIDField()
    encrypted_payload = serializers.CharField()
    nonce = serializers.CharField()
    crypto_version = serializers.IntegerField(min_value=1, max_value=32767, default=1)
    encryption_algorithm = serializers.CharField(max_length=32, default='xchacha20poly1305')

    _NONCE_LENGTH_BY_ALGORITHM = {
        'xchacha20poly1305': 24,
    }

    def validate_group(self, value):
        try:
            self._group_obj = Group.objects.get(uuid=value)
        except Group.DoesNotExist as exc:
            raise serializers.ValidationError('Group not found.') from exc
        return value

    def validate_encryption_algorithm(self, value):
        allowed_algorithms = tuple(
            getattr(settings, 'ALLOWED_IMAGE_ENCRYPTION_ALGORITHMS', ('xchacha20poly1305',)),
        )
        if value not in allowed_algorithms:
            raise serializers.ValidationError('Unsupported encryption_algorithm.')
        return value

    def validate_encrypted_payload(self, value):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise serializers.ValidationError('encrypted_payload must be valid base64.') from exc
        if not decoded:
            raise serializers.ValidationError('encrypted_payload cannot be empty.')
        return value

    def validate_nonce(self, value):
        try:
            base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise serializers.ValidationError('nonce must be valid base64.') from exc
        if not base64.b64decode(value, validate=True):
            raise serializers.ValidationError('nonce cannot be empty.')
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        attrs['group_obj'] = getattr(self, '_group_obj', None)

        algorithm = attrs.get('encryption_algorithm')
        nonce_b64 = attrs.get('nonce')
        if algorithm and nonce_b64:
            expected_len = self._NONCE_LENGTH_BY_ALGORITHM.get(algorithm)
            if expected_len is not None:
                nonce = base64.b64decode(nonce_b64, validate=True)
                if len(nonce) != expected_len:
                    raise serializers.ValidationError(
                        {
                            'nonce': (
                                f'Invalid nonce length for {algorithm}. '
                                f'Expected {expected_len} bytes.'
                            ),
                        },
                    )
        return attrs

