import hashlib
import os
import shutil
import tempfile
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from eyesonly.models import EncryptedImage, Group

User = get_user_model()


class TestDeleteExpiredImagesCommand(TestCase):
    def setUp(self):
        self.media_root = tempfile.mkdtemp()
        self.user = User.objects.create_user(username='cron-uploader', password='testpass')
        self.group = Group.objects.create(
            encrypted_name='cron-group',
            name_nonce=os.urandom(24),
        )

    def tearDown(self):
        shutil.rmtree(self.media_root, ignore_errors=True)

    def _create_image(self, filename, expires_at):
        ciphertext = os.urandom(64)
        return EncryptedImage.objects.create(
            encrypted_blob=SimpleUploadedFile(
                filename,
                ciphertext,
                content_type='application/octet-stream',
            ),
            group=self.group,
            uploaded_by=self.user,
            payload_nonce=os.urandom(24),
            ciphertext_hash_sha256=hashlib.sha256(ciphertext).hexdigest(),
            expires_at=expires_at,
        )

    def test_command_deletes_only_expired_images(self):
        now = timezone.now()

        with override_settings(ENCRYPTED_IMAGES_ROOT=os.path.join(self.media_root, 'encrypted_images')):
            expired_image = self._create_image(
                filename='expired.bin',
                expires_at=now - timedelta(minutes=5),
            )
            active_image = self._create_image(
                filename='active.bin',
                expires_at=now + timedelta(minutes=5),
            )
            no_expiry_image = self._create_image(
                filename='no_expiry.bin',
                expires_at=None,
            )

            call_command('check_eyesonly_encrypted_images')

        self.assertFalse(EncryptedImage.objects.filter(id=expired_image.id).exists())
        self.assertTrue(EncryptedImage.objects.filter(id=active_image.id).exists())
        self.assertTrue(EncryptedImage.objects.filter(id=no_expiry_image.id).exists())

    def test_command_dry_run_does_not_delete_images(self):
        now = timezone.now()

        with override_settings(ENCRYPTED_IMAGES_ROOT=os.path.join(self.media_root, 'encrypted_images')):
            expired_image = self._create_image(
                filename='dry_run_expired.bin',
                expires_at=now - timedelta(minutes=5),
            )

            call_command('check_eyesonly_encrypted_images', '--dry-run')

        self.assertTrue(EncryptedImage.objects.filter(id=expired_image.id).exists())
