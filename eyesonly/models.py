from django.db import models
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.storage import FileSystemStorage
from django.utils import timezone
from datetime import timedelta
import hashlib
import os
import uuid

from eyesonly.authentication.device_challenge_crypto import DEFAULT_KEY_WRAP_ALGORITHM

from fcm_django.models import FCMDevice

User = get_user_model()


class Organization(models.Model):
    name = models.CharField(max_length=255)
    max_groups = models.PositiveIntegerField(default=1, null=True)  # limit to prevent abuse and control costs
    max_devices = models.PositiveIntegerField(default=5, null=True)  # limit to prevent abuse and control costs
    max_images = models.PositiveIntegerField(default=50, null=True)  # limit to prevent abuse and control costs
    
    def __str__(self):
        return self.name


def get_organization_name() -> str:
    """Return the name of the first Organization row, or a fallback."""
    return Organization.objects.values_list('name', flat=True).first() or 'Unnamed Organization'


class EncryptedImageStorage(FileSystemStorage):
    @property
    def base_location(self):
        return os.path.abspath(str(getattr(settings, 'ENCRYPTED_IMAGES_ROOT', 'encrypted_images')))

    @property
    def location(self):
        return self.base_location

    @property
    def base_url(self):
        return None


encrypted_image_storage = EncryptedImageStorage()


def generate_public_key_fingerprint(public_key):
    """Return a stable SHA-256 hex fingerprint for public key material."""
    if isinstance(public_key, bytes):
        key_bytes = public_key
    else:
        normalized_key = str(public_key).strip().replace('\r\n', '\n')
        key_bytes = normalized_key.encode('utf-8')
    return hashlib.sha256(key_bytes).hexdigest()


def hash_device_auth_challenge(challenge_value):
    """Return a stable SHA-256 hex digest for a challenge value."""
    if isinstance(challenge_value, bytes):
        challenge_bytes = challenge_value
    else:
        challenge_bytes = str(challenge_value).encode('utf-8')
    return hashlib.sha256(challenge_bytes).hexdigest()

# not storing the public key here would mean that if a second manager enters the group and tries to share an image,
# they would have to do a new in-person pairing with each device that was already paired with the first manager,
# which would be a bad user experience.
# only the main manager of a group can add new devices to the group,
# so we can trust that they will only add devices that belong to other managers or devices of the same group
# new Device requires a new registration flow, so we can validate the public key and its fingerprint at the time of device creation and reject invalid ones.
class Device(models.Model):
    device_identifier = models.CharField(max_length=255, unique=True)
    owner_user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='owned_devices')
    # Public key material can be shared safely and lets any authorized manager device
    # encrypt a content key for this device without a new in-person pairing.
    public_key = models.TextField()
    public_key_algorithm = models.CharField(max_length=32, default='x25519')
    public_key_fingerprint = models.CharField(max_length=64) # short identifier for a public key
    
    fcm_device = models.OneToOneField(FCMDevice, null=True, on_delete=models.SET_NULL, related_name='eyesonly_device')

    def save(self, *args, **kwargs):
        computed_fingerprint = generate_public_key_fingerprint(self.public_key)
        # Always update fingerprint to match the public key
        self.public_key_fingerprint = computed_fingerprint
        super().save(*args, **kwargs)
        
    def __str__(self):
        return f'Device {self.device_identifier}'


class Group(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    encrypted_name = models.TextField()
    crypto_version = models.PositiveSmallIntegerField(default=1)
    encryption_algorithm = models.CharField(max_length=32, default='xchacha20poly1305')
    name_nonce = models.BinaryField(max_length=24)
    managers = models.ManyToManyField(User, through='ManagerRole', related_name='eyesonly_groups')
    
    def __str__(self):
        return str(self.uuid)
    

MANAGER_ROLES = (
    ('main_manager', 'Main manager'),
    ('manager', 'Manager'),
)

class ManagerRole(models.Model):
    manager = models.ForeignKey(User, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    role = models.CharField(max_length=255, choices=MANAGER_ROLES)
    
    def __str__(self):
        return f'{self.manager.username} is {self.role} of group {self.group.uuid}'
    
    class Meta:
        unique_together = ('manager', 'group')
    
    
class GroupDevices(models.Model):
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    encrypted_member_name = models.TextField(null=True, blank=True)
    can_delete_images = models.BooleanField(default=True)
    
    def __str__(self):
        return f'Device {self.device.device_identifier} in group {self.group.uuid} (can_delete_images={self.can_delete_images})'
    
    class Meta:
        unique_together = ('group', 'device')
        
        
GROUP_KEY_SCOPE_GROUP_SHARED = 'group_shared' # all group devices can decrypt this type of group key envelope
GROUP_KEY_SCOPE_MANAGER_ROSTER = 'manager_roster' # only managers can decrypt this type of group key envelope
GROUP_KEY_SCOPES = (
    (GROUP_KEY_SCOPE_GROUP_SHARED, 'Group shared'),
    (GROUP_KEY_SCOPE_MANAGER_ROSTER, 'Manager roster'),
)


class GroupKeyEnvelope(models.Model):
    group = models.ForeignKey(
        Group,
        on_delete=models.CASCADE,
        related_name='key_envelopes',
    )
    recipient_device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name='group_key_envelopes',
    )
    scope = models.CharField(max_length=32, choices=GROUP_KEY_SCOPES, default=GROUP_KEY_SCOPE_GROUP_SHARED)
    # Algorithm used to wrap the shared group metadata key for one recipient.
    key_wrap_algorithm = models.CharField(max_length=32, default=DEFAULT_KEY_WRAP_ALGORITHM)
    # Records which recipient public key was used when this envelope was created.
    recipient_key_fingerprint = models.CharField(max_length=64)
    # Stores the shared group metadata key encrypted for one specific recipient device.
    encrypted_group_key = models.BinaryField()

    class Meta:
        unique_together = ('group', 'recipient_device', 'scope')
        


def get_encrypted_blob_upload_path(instance, filename):
    _, extension = os.path.splitext(os.path.basename(filename) or 'encrypted_blob.bin')
    unique_filename = f'{uuid.uuid4().hex}{extension or ".bin"}'
    return os.path.join(str(instance.group_id), unique_filename)


def default_encrypted_image_expires_at():
    return timezone.now() + timedelta(weeks=2)

class EncryptedImage(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    # This file is already encrypted on the client before upload.
    # every single blob is encrypted using a dedicated content key,
    # and the content key is encrypted for each recipient device and stored in the RecipientEnvelope model.
    encrypted_blob = models.FileField(
        storage=encrypted_image_storage,
        upload_to=get_encrypted_blob_upload_path,
    )
    encrypted_caption = models.TextField(null=True)  # optional encrypted caption provided by the user
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='uploaded_encrypted_images',
        null=True,
    )
    # Allows mobile apps to evolve the crypto format over time.
    crypto_version = models.PositiveSmallIntegerField(default=1)
    # Algorithm used to encrypt the image payload itself.
    encryption_algorithm = models.CharField(max_length=32, default='xchacha20poly1305')
    # Nonce/IV used for payload encryption.
    payload_nonce = models.BinaryField(max_length=24, null=True)
    # Hash of the encrypted blob stored by the backend.
    ciphertext_hash_sha256 = models.CharField(max_length=64)
    expires_at = models.DateTimeField(null=True, default=default_encrypted_image_expires_at)
    created_at = models.DateTimeField(auto_now_add=True)

    def delete(self, *args, deleted_by_user=None, deleted_by_device=None, **kwargs):
        # Intentionally ignore actor metadata to avoid persisting post-delete traces.
        super().delete(*args, **kwargs)


class RecipientEnvelope(models.Model):
    encrypted_image = models.ForeignKey(
        EncryptedImage,
        on_delete=models.CASCADE,
        related_name='recipient_envelopes',
    )
    recipient_device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name='recipient_envelopes',
    )
    # Algorithm used to wrap the per-image content key for recipients.
    key_wrap_algorithm = models.CharField(max_length=32, default=DEFAULT_KEY_WRAP_ALGORITHM)
    # Records which recipient public key was used when this envelope was created.
    recipient_key_fingerprint = models.CharField(max_length=64)
    # Stores the per-image content key encrypted for one specific recipient device.
    # the content key is the secret key that was used to encrype the image
    # the manager device encrypts the content key for each recipient device using the recipient's public key and stores it in this field.
    encrypted_content_key = models.BinaryField()
    
    class Meta:
        unique_together = ('encrypted_image', 'recipient_device')
        
        
class DeviceAuthChallenge(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    challenge_hash = models.CharField(max_length=64)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def __str__(self):
        return f'Auth challenge for device {self.device.device_identifier} (hash: {self.challenge_hash})'
    
    class Meta:
        unique_together = ('device', 'challenge_hash')
    
    
class DeviceAuthToken(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    token_hash = models.CharField(max_length=255, unique=True)
    expires_at = models.DateTimeField()
    is_revoked = models.BooleanField(default=False)