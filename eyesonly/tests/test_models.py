import hashlib
import os
import shutil
import tempfile
from datetime import timedelta

from django.db import IntegrityError
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.utils import timezone

from eyesonly.authentication.device_challenge_crypto import DEFAULT_KEY_WRAP_ALGORITHM
from eyesonly.models import (Device, Group, ManagerRole, GroupDevices, EncryptedImage, RecipientEnvelope,
                             GroupKeyEnvelope, DeviceAuthChallenge, DeviceAuthToken,
                             generate_public_key_fingerprint, hash_device_auth_challenge)

User = get_user_model()


def create_group(encrypted_name='encrypted_group_name'):
    return Group.objects.create(
        encrypted_name=encrypted_name,
        name_nonce=os.urandom(24),
    )

class TestDeviceModel(TestCase):

    def test_device_creation(self):
        public_key = 'public_key_material'
        device = Device.objects.create(
            device_identifier='device123',
            public_key=public_key,
            public_key_algorithm='x25519',
        )
        self.assertEqual(device.device_identifier, 'device123')
        self.assertEqual(device.public_key, public_key)
        self.assertEqual(device.public_key_algorithm, 'x25519')
        self.assertEqual(device.public_key_fingerprint, generate_public_key_fingerprint(public_key))

    def test_public_key_change_recomputes_fingerprint(self):
        device = Device.objects.create(
            device_identifier='device-immutable',
            public_key='initial_public_key',
            public_key_algorithm='x25519',
        )

        device.public_key = 'changed_public_key'
        device.save()

        self.assertEqual(device.public_key, 'changed_public_key')
        self.assertEqual(
            device.public_key_fingerprint,
            generate_public_key_fingerprint('changed_public_key'),
        )

    def test_public_key_fingerprint_is_overwritten_from_public_key(self):
        device = Device.objects.create(
            device_identifier='device-fingerprint-mismatch',
            public_key='public_key_material',
            public_key_algorithm='x25519',
            public_key_fingerprint='not_the_real_fingerprint',
        )

        self.assertEqual(
            device.public_key_fingerprint,
            generate_public_key_fingerprint('public_key_material'),
        )
        
        
class TestGroupModel(TestCase):

    def test_group_creation(self):
        group = create_group('encrypted_test_group')
        self.assertEqual(group.encrypted_name, 'encrypted_test_group')
        self.assertEqual(group.crypto_version, 1)
        self.assertEqual(group.encryption_algorithm, 'xchacha20poly1305')
        self.assertEqual(len(bytes(group.name_nonce)), 24)
        self.assertEqual(str(group), str(group.uuid))

        
    def test_add_manager(self):
        user1 = User.objects.create_user(username='mainmanager', password='testpass')
        user2 = User.objects.create_user(username='manager', password='testpass')
        group = create_group('encrypted_test_group')
        ManagerRole.objects.create(manager=user1, group=group, role='main_manager')
        ManagerRole.objects.create(manager=user2, group=group, role='manager')
        
        self.assertIn(group, user1.eyesonly_groups.all())
        self.assertIn(group, user2.eyesonly_groups.all())
        
        
class TestManagerRoleModel(TestCase):

    def test_manager_role_creation(self):
        user = User.objects.create_user(username='manager', password='testpass')
        group = create_group('encrypted_test_group')
        manager_role = ManagerRole.objects.create(manager=user, group=group, role='manager')
        
        self.assertEqual(manager_role.manager, user)
        self.assertEqual(manager_role.group, group)
        self.assertEqual(manager_role.role, 'manager')
        
        # test main manager role creation
        user2 = User.objects.create_user(username='mainmanager', password='testpass')
        main_manager_role = ManagerRole.objects.create(manager=user2, group=group, role='main_manager')
        self.assertEqual(main_manager_role.manager, user2)
        self.assertEqual(main_manager_role.group, group)
        self.assertEqual(main_manager_role.role, 'main_manager')

    def test_manager_role_unique_together(self):
        user = User.objects.create_user(username='manager_unique', password='testpass')
        group = create_group('encrypted_unique_group')

        ManagerRole.objects.create(manager=user, group=group, role='manager')
        with self.assertRaises(IntegrityError):
            ManagerRole.objects.create(manager=user, group=group, role='main_manager')
        
        
class TestGroupDevicesModel(TestCase):

    def test_group_devices_creation(self):
        group = create_group('encrypted_test_group')
        device = Device.objects.create(
            device_identifier='device123',
            public_key='public_key_material',
            public_key_algorithm='x25519',
        )
        group_device = GroupDevices.objects.create(
            group=group,
            device=device,
            encrypted_member_name='encrypted_member_name',
            can_delete_images=True,
        )
        
        self.assertEqual(group_device.group, group)
        self.assertEqual(group_device.device, device)
        self.assertEqual(group_device.encrypted_member_name, 'encrypted_member_name')
        self.assertTrue(group_device.can_delete_images)

    def test_group_devices_unique_together(self):
        group = create_group('encrypted_unique_devices_group')
        device = Device.objects.create(
            device_identifier='device-unique-group-devices',
            public_key='public_key_material_unique_group_devices',
            public_key_algorithm='x25519',
        )

        GroupDevices.objects.create(group=group, device=device, can_delete_images=True)
        with self.assertRaises(IntegrityError):
            GroupDevices.objects.create(group=group, device=device, can_delete_images=False)
        
        
class TestEncryptedImageModel(TestCase):

    def setUp(self):
        self.media_root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.media_root, ignore_errors=True)

    def _encrypted_images_root(self):
        return os.path.join(self.media_root, 'encrypted_images')

    def _create_encrypted_image(self, group, user, filename='payload.bin', encrypted_caption=None):
        ciphertext = os.urandom(64)
        payload_nonce = os.urandom(24)
        ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
        return EncryptedImage.objects.create(
            encrypted_blob=SimpleUploadedFile(
                filename,
                ciphertext,
                content_type='application/octet-stream',
            ),
            encrypted_caption=encrypted_caption,
            group=group,
            uploaded_by=user,
            payload_nonce=payload_nonce,
            ciphertext_hash_sha256=ciphertext_hash,
        )

    def test_encrypted_image_creation(self):
        user = User.objects.create_user(username='uploader', password='testpass')
        group = create_group('encrypted_test_group')

        # Simulate a client-encrypted blob: opaque binary ciphertext
        ciphertext = os.urandom(64)
        ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
        payload_nonce = os.urandom(24) # number used once
        blob = SimpleUploadedFile('payload.bin', ciphertext, content_type='application/octet-stream')
        
        # this test uses a folder in /tmp for media
        # print(self.media_root)

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = EncryptedImage.objects.create(
                encrypted_blob=blob,
                group=group,
                uploaded_by=user,
                payload_nonce=payload_nonce,
                ciphertext_hash_sha256=ciphertext_hash,
            )

        self.assertEqual(encrypted_image.group, group)
        self.assertEqual(encrypted_image.uploaded_by, user)
        self.assertEqual(encrypted_image.ciphertext_hash_sha256, ciphertext_hash)
        self.assertEqual(encrypted_image.crypto_version, 1)
        self.assertEqual(encrypted_image.encryption_algorithm, 'xchacha20poly1305')
        self.assertEqual(bytes(encrypted_image.payload_nonce), payload_nonce)
        self.assertTrue(encrypted_image.encrypted_blob.name.endswith('.bin'))
        self.assertIsNone(encrypted_image.encrypted_caption)

    def test_encrypted_image_creation_with_encrypted_caption(self):
        user = User.objects.create_user(username='uploader_with_caption', password='testpass')
        group = create_group('encrypted_caption_group')

        encrypted_caption = 'base64:4A8x7hJ9M2qvW0sL6rQ='
        ciphertext = os.urandom(64)
        ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
        payload_nonce = os.urandom(24)
        blob = SimpleUploadedFile('payload_with_caption.bin', ciphertext, content_type='application/octet-stream')

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = EncryptedImage.objects.create(
                encrypted_blob=blob,
                encrypted_caption=encrypted_caption,
                group=group,
                uploaded_by=user,
                payload_nonce=payload_nonce,
                ciphertext_hash_sha256=ciphertext_hash,
            )

        encrypted_image.refresh_from_db()
        self.assertEqual(encrypted_image.encrypted_caption, encrypted_caption)

    def test_encrypted_image_creation_accepts_absolute_encrypted_images_root_setting(self):
        user = User.objects.create_user(username='uploader_absolute_folder', password='testpass')
        group = create_group('encrypted_absolute_folder_group')

        ciphertext = os.urandom(64)
        ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
        payload_nonce = os.urandom(24)
        blob = SimpleUploadedFile('encrypted_blob.bin', ciphertext, content_type='application/octet-stream')
        absolute_folder = self._encrypted_images_root()

        with override_settings(ENCRYPTED_IMAGES_ROOT=absolute_folder):
            encrypted_image = EncryptedImage.objects.create(
                encrypted_blob=blob,
                group=group,
                uploaded_by=user,
                payload_nonce=payload_nonce,
                ciphertext_hash_sha256=ciphertext_hash,
            )

            stored_name = encrypted_image.encrypted_blob.name
            self.assertTrue(stored_name.startswith(f'{group.id}/'))
            self.assertTrue(stored_name.endswith('.bin'))
            self.assertTrue(os.path.exists(encrypted_image.encrypted_blob.path))

    def test_encrypted_blob_byte_integrity(self):
        user = User.objects.create_user(username='integrity_uploader', password='testpass')
        group = create_group('encrypted_integrity_group')

        original_ciphertext = os.urandom(512)
        ciphertext_hash = hashlib.sha256(original_ciphertext).hexdigest()
        payload_nonce = os.urandom(24)
        blob = SimpleUploadedFile(
            'integrity_payload.bin',
            original_ciphertext,
            content_type='application/octet-stream',
        )

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = EncryptedImage.objects.create(
                encrypted_blob=blob,
                group=group,
                uploaded_by=user,
                payload_nonce=payload_nonce,
                ciphertext_hash_sha256=ciphertext_hash,
            )

            with encrypted_image.encrypted_blob.open('rb') as stored_blob:
                stored_ciphertext = stored_blob.read()

        self.assertEqual(stored_ciphertext, original_ciphertext)
        self.assertEqual(hashlib.sha256(stored_ciphertext).hexdigest(), encrypted_image.ciphertext_hash_sha256)
        
        
    def test_delete_with_user_actor_removes_image_without_audit_persistence(self):
        uploader = User.objects.create_user(username='uploader_delete_user', password='testpass')
        deleter = User.objects.create_user(
            username='deleter_user',
            password='testpass',
            first_name='Delete',
            last_name='User',
        )
        group = create_group('encrypted_delete_user_group')

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = self._create_encrypted_image(group=group, user=uploader, filename='delete_user.bin')
            image_id = encrypted_image.id

            encrypted_image.delete(deleted_by_user=deleter)

        self.assertFalse(EncryptedImage.objects.filter(id=image_id).exists())

    def test_delete_with_device_actor_removes_image_without_audit_persistence(self):
        uploader = User.objects.create_user(username='uploader_delete_device', password='testpass')
        group = create_group('encrypted_delete_device_group')
        deleting_device = Device.objects.create(
            device_identifier='device-delete-actor',
            public_key='device_delete_public_key',
            public_key_algorithm='x25519',
        )

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = self._create_encrypted_image(group=group, user=uploader, filename='delete_device.bin')
            image_id = encrypted_image.id

            encrypted_image.delete(deleted_by_device=deleting_device)

        self.assertFalse(EncryptedImage.objects.filter(id=image_id).exists())

    def test_delete_accepts_no_actor_or_both_actors_without_persistence(self):
        uploader = User.objects.create_user(username='uploader_delete_validation', password='testpass')
        deleter = User.objects.create_user(username='deleter_validation', password='testpass')
        group = create_group('encrypted_delete_validation_group')
        deleting_device = Device.objects.create(
            device_identifier='device-delete-validation',
            public_key='device_validation_public_key',
            public_key_algorithm='x25519',
        )

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            image_without_actor = self._create_encrypted_image(group=group, user=uploader, filename='delete_no_actor.bin')
            image_with_both_actors = self._create_encrypted_image(group=group, user=uploader, filename='delete_both_actor.bin')

            image_without_actor.delete()
            image_with_both_actors.delete(deleted_by_user=deleter, deleted_by_device=deleting_device)

        self.assertFalse(EncryptedImage.objects.filter(id=image_without_actor.id).exists())
        self.assertFalse(EncryptedImage.objects.filter(id=image_with_both_actors.id).exists())

    def test_delete_removes_file_from_disk(self):
        uploader = User.objects.create_user(username='uploader_file_removal', password='testpass')
        group = create_group('encrypted_file_removal_group')

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = self._create_encrypted_image(
                group=group,
                user=uploader,
                filename='file_removal_test.bin',
            )
            file_path = encrypted_image.encrypted_blob.path

            self.assertTrue(os.path.exists(file_path))

            encrypted_image.delete()

            self.assertFalse(os.path.exists(file_path))

    def test_queryset_delete_removes_file_from_disk(self):
        uploader = User.objects.create_user(username='uploader_queryset_removal', password='testpass')
        group = create_group('encrypted_queryset_removal_group')

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = self._create_encrypted_image(
                group=group,
                user=uploader,
                filename='queryset_removal_test.bin',
            )
            image_id = encrypted_image.id
            file_path = encrypted_image.encrypted_blob.path

            self.assertTrue(os.path.exists(file_path))

            EncryptedImage.objects.filter(id=image_id).delete()

            self.assertFalse(EncryptedImage.objects.filter(id=image_id).exists())
            self.assertFalse(os.path.exists(file_path))

    def test_group_delete_cascade_removes_file_from_disk(self):
        uploader = User.objects.create_user(username='uploader_cascade_removal', password='testpass')
        group = create_group('encrypted_cascade_removal_group')

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = self._create_encrypted_image(
                group=group,
                user=uploader,
                filename='cascade_removal_test.bin',
            )
            image_id = encrypted_image.id
            file_path = encrypted_image.encrypted_blob.path

            self.assertTrue(os.path.exists(file_path))

            group.delete()

            self.assertFalse(EncryptedImage.objects.filter(id=image_id).exists())
            self.assertFalse(os.path.exists(file_path))
        
        
class TestRecipientEnvelopeModel(TestCase):

    def setUp(self):
        self.media_root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.media_root, ignore_errors=True)

    def _encrypted_images_root(self):
        return os.path.join(self.media_root, 'encrypted_images')

    def test_recipient_envelope_creation(self):
        user = User.objects.create_user(username='uploader', password='testpass')
        group = create_group('encrypted_test_group')
        device = Device.objects.create(
            device_identifier='device123',
            public_key='public_key_material',
            public_key_algorithm='x25519',
        )

        ciphertext = os.urandom(64)
        payload_nonce = os.urandom(24)
        ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = EncryptedImage.objects.create(
                encrypted_blob=SimpleUploadedFile(
                    'payload.bin',
                    ciphertext,
                    content_type='application/octet-stream',
                ),
                group=group,
                uploaded_by=user,
                payload_nonce=payload_nonce,
                ciphertext_hash_sha256=ciphertext_hash,
            )

            encrypted_content_key = os.urandom(64)
            key_fingerprint = generate_public_key_fingerprint(device.public_key)

            recipient_envelope = RecipientEnvelope.objects.create(
                encrypted_image=encrypted_image,
                recipient_device=device,
                recipient_key_fingerprint=key_fingerprint,
                encrypted_content_key=encrypted_content_key,
            )

        self.assertEqual(recipient_envelope.encrypted_image, encrypted_image)
        self.assertEqual(recipient_envelope.recipient_device, device)
        self.assertEqual(recipient_envelope.key_wrap_algorithm, DEFAULT_KEY_WRAP_ALGORITHM)
        self.assertEqual(recipient_envelope.recipient_key_fingerprint, key_fingerprint)
        self.assertEqual(bytes(recipient_envelope.encrypted_content_key), encrypted_content_key)

    def test_recipient_envelope_unique_together(self):
        user = User.objects.create_user(username='uploader_unique_envelope', password='testpass')
        group = create_group('encrypted_envelope_unique_group')
        device = Device.objects.create(
            device_identifier='device-unique-envelope',
            public_key='public_key_material_unique_envelope',
            public_key_algorithm='x25519',
        )

        ciphertext = os.urandom(64)
        payload_nonce = os.urandom(24)
        ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()

        with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
            encrypted_image = EncryptedImage.objects.create(
                encrypted_blob=SimpleUploadedFile(
                    'payload.bin',
                    ciphertext,
                    content_type='application/octet-stream',
                ),
                group=group,
                uploaded_by=user,
                payload_nonce=payload_nonce,
                ciphertext_hash_sha256=ciphertext_hash,
            )

            key_fingerprint = generate_public_key_fingerprint(device.public_key)
            RecipientEnvelope.objects.create(
                encrypted_image=encrypted_image,
                recipient_device=device,
                recipient_key_fingerprint=key_fingerprint,
                encrypted_content_key=os.urandom(64),
            )

            with self.assertRaises(IntegrityError):
                RecipientEnvelope.objects.create(
                    encrypted_image=encrypted_image,
                    recipient_device=device,
                    recipient_key_fingerprint=key_fingerprint,
                    encrypted_content_key=os.urandom(64),
                )


class TestGroupKeyEnvelopeModel(TestCase):

    def test_group_key_envelope_creation(self):
        group = create_group('encrypted_group_key_group')
        device = Device.objects.create(
            device_identifier='device-group-key-envelope',
            public_key='public_key_material_group_key_envelope',
            public_key_algorithm='x25519',
        )
        key_fingerprint = generate_public_key_fingerprint(device.public_key)
        encrypted_group_key = os.urandom(64)

        group_key_envelope = GroupKeyEnvelope.objects.create(
            group=group,
            recipient_device=device,
            recipient_key_fingerprint=key_fingerprint,
            encrypted_group_key=encrypted_group_key,
        )

        self.assertEqual(group_key_envelope.group, group)
        self.assertEqual(group_key_envelope.recipient_device, device)
        self.assertEqual(group_key_envelope.key_wrap_algorithm, DEFAULT_KEY_WRAP_ALGORITHM)
        self.assertEqual(group_key_envelope.recipient_key_fingerprint, key_fingerprint)
        self.assertEqual(bytes(group_key_envelope.encrypted_group_key), encrypted_group_key)

    def test_group_key_envelope_unique_together(self):
        group = create_group('encrypted_group_key_unique_group')
        device = Device.objects.create(
            device_identifier='device-group-key-envelope-unique',
            public_key='public_key_material_group_key_envelope_unique',
            public_key_algorithm='x25519',
        )
        key_fingerprint = generate_public_key_fingerprint(device.public_key)

        GroupKeyEnvelope.objects.create(
            group=group,
            recipient_device=device,
            recipient_key_fingerprint=key_fingerprint,
            encrypted_group_key=os.urandom(64),
        )

        with self.assertRaises(IntegrityError):
            GroupKeyEnvelope.objects.create(
                group=group,
                recipient_device=device,
                recipient_key_fingerprint=key_fingerprint,
                encrypted_group_key=os.urandom(64),
            )

   
class TestDeviceAuthChallengeModel(TestCase):
    def test_device_auth_challenge_creation(self):
        device = Device.objects.create(
            device_identifier='device-auth-challenge-1',
            public_key='device_auth_challenge_public_key',
            public_key_algorithm='x25519',
        )

        now = timezone.now()
        expires_at = now + timedelta(minutes=5)
        challenge_value = 'challenge-token-123'
        challenge = DeviceAuthChallenge.objects.create(
            device=device,
            challenge_hash=hash_device_auth_challenge(challenge_value),
            expires_at=expires_at,
        )

        self.assertEqual(challenge.device, device)
        self.assertEqual(challenge.challenge_hash, hash_device_auth_challenge(challenge_value))
        self.assertEqual(challenge.expires_at, expires_at)
        self.assertFalse(challenge.is_used)

    def test_device_auth_challenge_unique_per_device(self):
        device = Device.objects.create(
            device_identifier='device-auth-challenge-2',
            public_key='device_auth_challenge_public_key_2',
            public_key_algorithm='x25519',
        )

        expires_at = timezone.now() + timedelta(minutes=5)
        challenge_hash = hash_device_auth_challenge('same-challenge-token')
        DeviceAuthChallenge.objects.create(
            device=device,
            challenge_hash=challenge_hash,
            expires_at=expires_at,
        )

        with self.assertRaises(IntegrityError):
            DeviceAuthChallenge.objects.create(
                device=device,
                challenge_hash=challenge_hash,
                expires_at=expires_at,
            )
            
class TestDeviceAuthTokenModel(TestCase):
    def test_device_auth_token_creation(self):
        device = Device.objects.create(
            device_identifier='device-auth-token-1',
            public_key='device_auth_token_public_key',
            public_key_algorithm='x25519',
        )

        now = timezone.now()
        expires_at = now + timedelta(days=30)
        token = DeviceAuthToken.objects.create(
            device=device,
            token_hash='token-hash-123',
            expires_at=expires_at,
        )

        self.assertEqual(token.device, device)
        self.assertEqual(token.token_hash, 'token-hash-123')
        self.assertEqual(token.expires_at, expires_at)
        self.assertFalse(token.is_revoked)

    def test_device_auth_token_hash_is_unique(self):
        device_one = Device.objects.create(
            device_identifier='device-auth-token-2',
            public_key='device_auth_token_public_key_2',
            public_key_algorithm='x25519',
        )
        device_two = Device.objects.create(
            device_identifier='device-auth-token-3',
            public_key='device_auth_token_public_key_3',
            public_key_algorithm='x25519',
        )

        expires_at = timezone.now() + timedelta(days=30)
        DeviceAuthToken.objects.create(
            device=device_one,
            token_hash='same-token-hash',
            expires_at=expires_at,
        )

        with self.assertRaises(IntegrityError):
            DeviceAuthToken.objects.create(
                device=device_two,
                token_hash='same-token-hash',
                expires_at=expires_at,
            )
            
class TestGetPublicKeyFingerprint(TestCase):
    def test_generate_public_key_fingerprint(self):
        public_key = 'test_public_key_material'
        expected_fingerprint = hashlib.sha256(public_key.encode('utf-8')).hexdigest()
        self.assertEqual(generate_public_key_fingerprint(public_key), expected_fingerprint)


