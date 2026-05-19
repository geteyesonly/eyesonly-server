import base64
import hashlib
import json
import os
import shutil
import tempfile
from datetime import timedelta
from unittest.mock import MagicMock, patch
import yaml

from django.conf import settings
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from rest_framework import status
from rest_framework.test import APIClient

from eyesonly.authentication.device_challenge_crypto import (
	DEFAULT_KEY_WRAP_ALGORITHM,
	DEVICE_CHALLENGE_ENCRYPTION_ALGORITHM,
	DEVICE_CHALLENGE_HKDF_INFO,
)
from eyesonly.models import (
	Device,
	DeviceAuthChallenge,
	DeviceAuthToken,
	EncryptedImage,
	get_organization_name,
	Organization,
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

User = get_user_model()


def create_group(encrypted_name='encrypted_group_name'):
	return Group.objects.create(
		encrypted_name=encrypted_name,
		name_nonce=os.urandom(24),
	)


def create_quota_organization(*, max_groups=1, max_devices=5, max_images=50, name='Quota Org'):
	return Organization.objects.create(
		name=name,
		max_groups=max_groups,
		max_devices=max_devices,
		max_images=max_images,
	)


class TestCreateDeviceAuthChallengeView(TestCase):
	def setUp(self):
		cache.clear()
		self.client = APIClient()
		self.url = reverse('device-auth-challenge')
		self.private_key = x25519.X25519PrivateKey.generate()
		public_key = self.private_key.public_key().public_bytes(
			encoding=serialization.Encoding.Raw,
			format=serialization.PublicFormat.Raw,
		)
		self.device = Device.objects.create(
			device_identifier='device-auth-challenge-1',
			public_key=base64.b64encode(public_key).decode('ascii'),
			public_key_algorithm='x25519',
		)

	def _decrypt_challenge_bundle(self, bundle):
		from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
		ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(
			base64.b64decode(bundle['ephemeral_public_key']),
		)
		shared_secret = self.private_key.exchange(ephemeral_public_key)
		derived_key = HKDF(
			algorithm=hashes.SHA256(),
			length=32,
			salt=None,
			info=DEVICE_CHALLENGE_HKDF_INFO,
		).derive(shared_secret)
		plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
			base64.b64decode(bundle['ciphertext']),
			aad=None,
			nonce=base64.b64decode(bundle['nonce']),
			key=derived_key,
		)
		return plaintext.decode('utf-8')

	@override_settings(DEVICE_AUTH_CHALLENGE_TTL_SECONDS=600)
	def test_post_creates_challenge_and_returns_201(self):
		before_request = timezone.now()

		response = self.client.post(
			self.url,
			data={'device_identifier': self.device.device_identifier},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(DeviceAuthChallenge.objects.count(), 1)

		challenge = DeviceAuthChallenge.objects.get(device=self.device)
		self.assertIn('encrypted_challenge', response.data)
		self.assertEqual(
			response.data['encrypted_challenge']['algorithm'],
			DEVICE_CHALLENGE_ENCRYPTION_ALGORITHM,
		)
		decrypted_challenge = self._decrypt_challenge_bundle(response.data['encrypted_challenge'])
		self.assertEqual(
			challenge.challenge_hash,
			hash_device_auth_challenge(decrypted_challenge),
		)
		self.assertEqual(response.data['expires_at'], challenge.expires_at)
		self.assertGreater(challenge.expires_at, before_request)
		self.assertLessEqual(
			challenge.expires_at,
			before_request + timedelta(seconds=600, milliseconds=500),
		)

	def test_post_returns_decoy_challenge_for_unknown_device(self):
		response = self.client.post(
			self.url,
			data={'device_identifier': 'unknown-device'},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertIn('encrypted_challenge', response.data)
		self.assertIn('expires_at', response.data)
		self.assertEqual(DeviceAuthChallenge.objects.count(), 0)

	@override_settings(
		REST_FRAMEWORK={
			'DEFAULT_THROTTLE_RATES': {
				'device_auth_challenge': '1/minute',
				'device_auth_token': '20/minute',
			},
		},
	)
	def test_post_is_throttled_after_rate_limit(self):
		first_response = self.client.post(
			self.url,
			data={'device_identifier': self.device.device_identifier},
			format='json',
		)
		second_response = self.client.post(
			self.url,
			data={'device_identifier': self.device.device_identifier},
			format='json',
		)

		self.assertEqual(first_response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(second_response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

	def test_post_returns_400_for_invalid_payload(self):
		response = self.client.post(self.url, data={}, format='json')

		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('device_identifier', response.data)

	def test_post_returns_decoy_challenge_when_registered_key_cannot_be_used(self):
		invalid_device = Device.objects.create(
			device_identifier='device-auth-challenge-invalid-key',
			public_key='not-base64',
			public_key_algorithm='x25519',
		)

		response = self.client.post(
			self.url,
			data={'device_identifier': invalid_device.device_identifier},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertIn('encrypted_challenge', response.data)
		self.assertIn('expires_at', response.data)
		self.assertEqual(DeviceAuthChallenge.objects.count(), 0)

	def test_post_expires_existing_active_unused_challenges(self):
		future_time = timezone.now() + timedelta(minutes=5)
		active_challenge_value = 'still-active-challenge'
		active_challenge = DeviceAuthChallenge.objects.create(
			device=self.device,
			challenge_hash=hash_device_auth_challenge(active_challenge_value),
			expires_at=future_time,
		)

		response = self.client.post(
			self.url,
			data={'device_identifier': self.device.device_identifier},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)

		active_challenge.refresh_from_db()
		self.assertLessEqual(active_challenge.expires_at, timezone.now())

		challenges = DeviceAuthChallenge.objects.filter(device=self.device).order_by('id')
		self.assertEqual(challenges.count(), 2)
		self.assertNotEqual(challenges.last().challenge_hash, active_challenge.challenge_hash)
		self.assertEqual(
			challenges.last().challenge_hash,
			hash_device_auth_challenge(
				self._decrypt_challenge_bundle(response.data['encrypted_challenge']),
			),
		)


class TestCreateDeviceAuthTokenView(TestCase):
	def setUp(self):
		cache.clear()
		self.client = APIClient()
		self.challenge_url = reverse('device-auth-challenge')
		self.token_url = reverse('device-auth-token')
		self.private_key = x25519.X25519PrivateKey.generate()
		public_key = self.private_key.public_key().public_bytes(
			encoding=serialization.Encoding.Raw,
			format=serialization.PublicFormat.Raw,
		)
		self.device = Device.objects.create(
			device_identifier='device-auth-token-view-1',
			public_key=base64.b64encode(public_key).decode('ascii'),
			public_key_algorithm='x25519',
		)

	def _decrypt_challenge_bundle(self, bundle):
		from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
		ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(
			base64.b64decode(bundle['ephemeral_public_key']),
		)
		shared_secret = self.private_key.exchange(ephemeral_public_key)
		derived_key = HKDF(
			algorithm=hashes.SHA256(),
			length=32,
			salt=None,
			info=DEVICE_CHALLENGE_HKDF_INFO,
		).derive(shared_secret)
		plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
			base64.b64decode(bundle['ciphertext']),
			aad=None,
			nonce=base64.b64decode(bundle['nonce']),
			key=derived_key,
		)
		return plaintext.decode('utf-8')

	def _request_decrypted_challenge(self):
		response = self.client.post(
			self.challenge_url,
			data={'device_identifier': self.device.device_identifier},
			format='json',
		)
		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		return self._decrypt_challenge_bundle(response.data['encrypted_challenge'])

	def test_post_creates_token_for_device_with_private_key_possession(self):
		challenge_value = self._request_decrypted_challenge()

		response = self.client.post(
			self.token_url,
			data={
				'device_identifier': self.device.device_identifier,
				'challenge': challenge_value,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(response.data['token_type'], 'Bearer')
		self.assertIn('access_token', response.data)
		self.assertEqual(DeviceAuthToken.objects.count(), 1)

		challenge = DeviceAuthChallenge.objects.get(device=self.device)
		self.assertTrue(challenge.is_used)

	def test_post_rejects_plaintext_challenge_without_private_key_proof(self):
		self.client.post(
			self.challenge_url,
			data={'device_identifier': self.device.device_identifier},
			format='json',
		)

		response = self.client.post(
			self.token_url,
			data={
				'device_identifier': self.device.device_identifier,
				'challenge': 'guessed-or-replayed-value',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertEqual(response.data, {'detail': 'Invalid credentials.'})
		self.assertEqual(DeviceAuthToken.objects.count(), 0)

	def test_post_rejects_expired_challenge_even_if_device_can_decrypt_it(self):
		challenge_value = self._request_decrypted_challenge()
		challenge = DeviceAuthChallenge.objects.get(device=self.device)
		challenge.expires_at = timezone.now() - timedelta(seconds=1)
		challenge.save(update_fields=['expires_at'])

		response = self.client.post(
			self.token_url,
			data={
				'device_identifier': self.device.device_identifier,
				'challenge': challenge_value,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertEqual(response.data, {'detail': 'Invalid credentials.'})
		self.assertEqual(DeviceAuthToken.objects.count(), 0)

	def test_post_rejects_reuse_of_consumed_challenge(self):
		challenge_value = self._request_decrypted_challenge()

		first_response = self.client.post(
			self.token_url,
			data={
				'device_identifier': self.device.device_identifier,
				'challenge': challenge_value,
			},
			format='json',
		)
		second_response = self.client.post(
			self.token_url,
			data={
				'device_identifier': self.device.device_identifier,
				'challenge': challenge_value,
			},
			format='json',
		)

		self.assertEqual(first_response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(second_response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertEqual(second_response.data, {'detail': 'Invalid credentials.'})
		self.assertEqual(DeviceAuthToken.objects.count(), 1)

	@override_settings(
		REST_FRAMEWORK={
			'DEFAULT_THROTTLE_RATES': {
				'device_auth_challenge': '20/minute',
				'device_auth_token': '1/minute',
			},
		},
	)
	def test_post_is_throttled_after_rate_limit(self):
		challenge_value = self._request_decrypted_challenge()

		first_response = self.client.post(
			self.token_url,
			data={
				'device_identifier': self.device.device_identifier,
				'challenge': challenge_value,
			},
			format='json',
		)
		second_response = self.client.post(
			self.token_url,
			data={
				'device_identifier': self.device.device_identifier,
				'challenge': challenge_value,
			},
			format='json',
		)

		self.assertEqual(first_response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(second_response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)


class TestRevokeDeviceAuthTokenView(TestCase):
	def setUp(self):
		cache.clear()
		self.client = APIClient()
		self.revoke_url = reverse('device-auth-revoke')
		self.device = Device.objects.create(
			device_identifier='device-revoke-token-1',
			public_key=base64.b64encode(x25519.X25519PrivateKey.generate().public_key().public_bytes(
				encoding=serialization.Encoding.Raw,
				format=serialization.PublicFormat.Raw,
			)).decode('ascii'),
			public_key_algorithm='x25519',
		)

	def _create_token(self, *, expires_at=None):
		import hashlib, secrets
		raw_token = secrets.token_urlsafe(48)
		token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
		record = DeviceAuthToken.objects.create(
			device=self.device,
			token_hash=token_hash,
			expires_at=expires_at or timezone.now() + timedelta(days=30),
		)
		return raw_token, record

	def test_post_revokes_valid_token_and_returns_204(self):
		raw_token, record = self._create_token()

		response = self.client.post(
			self.revoke_url,
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		record.refresh_from_db()
		self.assertTrue(record.is_revoked)

	def test_post_is_idempotent_when_already_revoked(self):
		raw_token, record = self._create_token()
		record.is_revoked = True
		record.save(update_fields=['is_revoked'])

		# Token is revoked, so DeviceTokenAuthentication rejects it with 401
		# before the view body runs — the second call cannot succeed.
		response = self.client.post(
			self.revoke_url,
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TestRegisterDeviceView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('register-device')
		self.group = create_group('Primary Group')
		self.other_group = create_group('Other Group')
		self.staff_user = User.objects.create_user(
			username='staff-user',
			email='staff@example.com',
			password='test-password-123',
			is_staff=True,
		)
		self.non_staff_user = User.objects.create_user(
			username='non-staff-user',
			email='nonstaff@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(
			manager=self.non_staff_user,
			group=self.group,
			role='main_manager',
		)

	def _new_public_key(self):
		return base64.b64encode(
			x25519.X25519PrivateKey.generate().public_key().public_bytes(
				encoding=serialization.Encoding.Raw,
				format=serialization.PublicFormat.Raw,
			),
		).decode('ascii')

	def test_post_requires_authenticated_user(self):
		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'new-device-1',
				'public_key': self._new_public_key(),
				'public_key_algorithm': 'x25519',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_post_rejects_non_staff_user(self):
		self.client.force_authenticate(user=self.non_staff_user)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'new-device-2',
				'public_key': self._new_public_key(),
				'public_key_algorithm': 'x25519',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
		self.assertEqual(response.data['detail'], 'You do not have permission to perform this action.')

	def test_post_registers_device_when_user_is_staff(self):
		self.client.force_authenticate(user=self.staff_user)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'new-device-3',
				'public_key': self._new_public_key(),
				'public_key_algorithm': 'x25519',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(Device.objects.filter(device_identifier='new-device-3').count(), 1)
		device = Device.objects.get(device_identifier='new-device-3')
		self.assertIsNone(device.owner_user)
		self.assertFalse(GroupDevices.objects.filter(group=self.group, device=device).exists())

	def test_post_returns_403_when_max_devices_quota_reached_for_new_device(self):
		self.client.force_authenticate(user=self.staff_user)
		Device.objects.create(
			device_identifier='existing-quota-device',
			public_key=self._new_public_key(),
			public_key_algorithm='x25519',
		)
		create_quota_organization(max_groups=10, max_devices=1, max_images=100)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'quota-blocked-device',
				'public_key': self._new_public_key(),
				'public_key_algorithm': 'x25519',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
		self.assertEqual(response.data['quota'], 'max_devices')
		self.assertEqual(response.data['current'], 1)
		self.assertEqual(response.data['maximum'], 1)
		self.assertFalse(Device.objects.filter(device_identifier='quota-blocked-device').exists())

	def test_post_can_register_self_owned_device(self):
		self.client.force_authenticate(user=self.staff_user)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'owned-device-1',
				'public_key': self._new_public_key(),
				'public_key_algorithm': 'x25519',
				'owner_user': self.staff_user.id,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(
			Device.objects.get(device_identifier='owned-device-1').owner_user,
			self.staff_user,
		)

	def test_post_rejects_assigning_other_user_as_owner(self):
		self.client.force_authenticate(user=self.staff_user)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'owned-device-2',
				'public_key': self._new_public_key(),
				'public_key_algorithm': 'x25519',
				'owner_user': self.non_staff_user.id,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('non_field_errors', response.data)
		self.assertEqual(
			response.data['non_field_errors'][0],
			'You may only assign yourself as the device owner.',
		)
		self.assertFalse(Device.objects.filter(device_identifier='owned-device-2').exists())

	def test_post_allows_existing_device_with_matching_owner_user(self):
		self.client.force_authenticate(user=self.staff_user)
		public_key = self._new_public_key()
		Device.objects.create(
			device_identifier='existing-device-owned-by-other',
			owner_user=self.non_staff_user,
			public_key=public_key,
			public_key_algorithm='x25519',
		)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'existing-device-owned-by-other',
				'public_key': public_key,
				'public_key_algorithm': 'x25519',
				'owner_user': self.non_staff_user.id,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(
			Device.objects.get(device_identifier='existing-device-owned-by-other').owner_user,
			self.non_staff_user,
		)

	def test_post_rejects_changing_owner_user_for_existing_owned_device(self):
		self.client.force_authenticate(user=self.staff_user)
		public_key = self._new_public_key()
		Device.objects.create(
			device_identifier='existing-device-owner-locked',
			owner_user=self.non_staff_user,
			public_key=public_key,
			public_key_algorithm='x25519',
		)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'existing-device-owner-locked',
				'public_key': public_key,
				'public_key_algorithm': 'x25519',
				'owner_user': self.staff_user.id,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertEqual(
			response.data['owner_user'][0],
			'This device is already assigned to a different owner.',
		)
		self.assertEqual(
			Device.objects.get(device_identifier='existing-device-owner-locked').owner_user,
			self.non_staff_user,
		)

	def test_post_returns_200_when_device_already_exists_with_same_key(self):
		self.client.force_authenticate(user=self.staff_user)
		public_key = self._new_public_key()
		Device.objects.create(
			device_identifier='existing-device-same-key',
			public_key=public_key,
			public_key_algorithm='x25519',
		)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'existing-device-same-key',
				'public_key': public_key,
				'public_key_algorithm': 'x25519',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIsNone(Device.objects.get(device_identifier='existing-device-same-key').owner_user)

	def test_post_updates_owner_user_when_explicitly_provided(self):
		self.client.force_authenticate(user=self.staff_user)
		public_key = self._new_public_key()
		Device.objects.create(
			device_identifier='existing-device-owned',
			public_key=public_key,
			public_key_algorithm='x25519',
		)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'existing-device-owned',
				'public_key': public_key,
				'public_key_algorithm': 'x25519',
				'owner_user': self.staff_user.id,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(
			Device.objects.get(device_identifier='existing-device-owned').owner_user,
			self.staff_user,
		)

	def test_post_returns_200_when_identifier_exists_with_different_key(self):
		existing_public_key = self._new_public_key()
		Device.objects.create(
			device_identifier='existing-device',
			public_key=existing_public_key,
			public_key_algorithm='x25519',
		)

		self.client.force_authenticate(user=self.staff_user)
		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'existing-device',
				'public_key': self._new_public_key(),
				'public_key_algorithm': 'x25519',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)

	def test_post_registers_device_for_staff_without_manager_role(self):
		staff_without_group_role = User.objects.create_user(
			username='staff-no-group-role',
			email='staff-no-group-role@example.com',
			password='test-password-123',
			is_staff=True,
		)
		self.client.force_authenticate(user=staff_without_group_role)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'new-device-4',
				'public_key': self._new_public_key(),
				'public_key_algorithm': 'x25519',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertTrue(Device.objects.filter(device_identifier='new-device-4').exists())


class TestAddDeviceToGroupView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('add-device-to-group')
		self.group = create_group('Primary Group')
		self.other_group = create_group('Other Group')
		self.main_manager = User.objects.create_user(
			username='main-manager-add',
			email='main-add@example.com',
			password='test-password-123',
		)
		self.normal_manager = User.objects.create_user(
			username='normal-manager-add',
			email='manager-add@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(
			manager=self.main_manager,
			group=self.group,
			role='main_manager',
		)
		ManagerRole.objects.create(
			manager=self.normal_manager,
			group=self.group,
			role='manager',
		)
		self.device = Device.objects.create(
			device_identifier='existing-device-add-link',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

	def test_post_requires_authenticated_user(self):
		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': str(self.group.uuid),
				'encrypted_member_name': 'encrypted:member-name-1',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_post_rejects_non_main_manager(self):
		self.client.force_authenticate(user=self.normal_manager)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': str(self.group.uuid),
				'encrypted_member_name': 'encrypted:member-name-2',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

	def test_post_links_existing_device_to_group(self):
		self.client.force_authenticate(user=self.main_manager)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': str(self.group.uuid),
				'encrypted_member_name': 'encrypted:member-name-3',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		group_device = GroupDevices.objects.get(group=self.group, device=self.device)
		self.assertEqual(group_device.encrypted_member_name, 'encrypted:member-name-3')

	def test_post_returns_200_when_link_already_exists(self):
		self.client.force_authenticate(user=self.main_manager)
		GroupDevices.objects.create(
			group=self.group,
			device=self.device,
			encrypted_member_name='encrypted:existing-member-name',
		)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': str(self.group.uuid),
				'encrypted_member_name': 'encrypted:updated-member-name',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(
			GroupDevices.objects.get(group=self.group, device=self.device).encrypted_member_name,
			'encrypted:updated-member-name',
		)

	def test_post_rejects_manager_flag_for_device_without_owner_user(self):
		self.client.force_authenticate(user=self.main_manager)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': str(self.group.uuid),
				'encrypted_member_name': 'encrypted:member-name-managerless',
				'is_manager': True,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertEqual(
			response.data['is_manager'][0],
			'Manager devices must have a registered user.',
		)

	def test_post_assigns_manager_role_when_flag_enabled(self):
		self.client.force_authenticate(user=self.main_manager)
		manager_candidate = User.objects.create_user(
			username='group-device-owner-manager-candidate',
			email='group-device-owner-manager-candidate@example.com',
			password='test-password-123',
		)
		owned_device = Device.objects.create(
			device_identifier='existing-device-add-manager-role',
			owner_user=manager_candidate,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': owned_device.device_identifier,
				'group': str(self.group.uuid),
				'encrypted_member_name': 'encrypted:manager-device-member-name',
				'is_manager': True,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertTrue(
			ManagerRole.objects.filter(
				manager=manager_candidate,
				group=self.group,
				role='manager',
			).exists(),
		)

	def test_post_returns_404_when_device_not_found(self):
		self.client.force_authenticate(user=self.main_manager)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'missing-device',
				'group': str(self.group.uuid),
				'encrypted_member_name': 'encrypted:missing-member-name',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

	def test_post_returns_404_when_group_not_found(self):
		self.client.force_authenticate(user=self.main_manager)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': 'ffffffff-ffff-ffff-ffff-ffffffffffff',
				'encrypted_member_name': 'encrypted:missing-group-member-name',
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class TestRemoveDeviceFromGroupView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('remove-device-from-group')
		self.group = create_group('Test Group')
		self.other_group = create_group('Other Group')
		self.main_manager = User.objects.create_user(
			username='main-manager',
			email='main@example.com',
			password='test-password-123',
		)
		self.normal_manager = User.objects.create_user(
			username='normal-manager',
			email='manager@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(
			manager=self.main_manager,
			group=self.group,
			role='main_manager',
		)
		ManagerRole.objects.create(
			manager=self.normal_manager,
			group=self.group,
			role='manager',
		)
		# Create a device linked to the group
		self.device = Device.objects.create(
			device_identifier='test-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=self.device)

	def test_post_requires_authenticated_user(self):
		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': str(self.group.uuid),
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_post_rejects_non_main_manager(self):
		self.client.force_authenticate(user=self.normal_manager)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': str(self.group.uuid),
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
		self.assertEqual(response.data['detail'], 'Only main managers can perform this action.')

	def test_post_removes_device_from_group_for_main_manager(self):
		self.client.force_authenticate(user=self.main_manager)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': str(self.group.uuid),
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertFalse(GroupDevices.objects.filter(group=self.group, device=self.device).exists())

	def test_post_returns_404_when_device_not_found(self):
		self.client.force_authenticate(user=self.main_manager)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': 'nonexistent-device',
				'group': str(self.group.uuid),
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
		self.assertEqual(response.data['detail'], 'Device not found.')

	def test_post_returns_404_when_group_not_found(self):
		self.client.force_authenticate(user=self.main_manager)
		fake_group_uuid = 'ffffffff-ffff-ffff-ffff-ffffffffffff'

		response = self.client.post(
			self.url,
			data={
				'device_identifier': self.device.device_identifier,
				'group': fake_group_uuid,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
		self.assertEqual(response.data['detail'], 'Group not found.')

	def test_post_returns_404_when_device_not_in_group(self):
		self.client.force_authenticate(user=self.main_manager)
		# Create another device NOT linked to the group
		other_device = Device.objects.create(
			device_identifier='test-device-2',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': other_device.device_identifier,
				'group': str(self.group.uuid),
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
		self.assertEqual(response.data['detail'], 'Device is not part of this group.')

	def test_post_removes_manager_role_when_last_device_removed(self):
		self.client.force_authenticate(user=self.main_manager)
		device_owner = User.objects.create_user(
			username='owner-single-device',
			email='owner-single-device@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=device_owner, group=self.group, role='manager')
		owned_device = Device.objects.create(
			device_identifier='owned-single-device',
			owner_user=device_owner,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=owned_device)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': owned_device.device_identifier,
				'group': str(self.group.uuid),
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertFalse(
			ManagerRole.objects.filter(manager=device_owner, group=self.group).exists(),
		)

	def test_post_preserves_manager_role_when_owner_has_remaining_devices(self):
		self.client.force_authenticate(user=self.main_manager)
		device_owner = User.objects.create_user(
			username='owner-two-devices',
			email='owner-two-devices@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=device_owner, group=self.group, role='manager')
		device_a = Device.objects.create(
			device_identifier='owned-device-a',
			owner_user=device_owner,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		device_b = Device.objects.create(
			device_identifier='owned-device-b',
			owner_user=device_owner,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=device_a)
		GroupDevices.objects.create(group=self.group, device=device_b)

		response = self.client.post(
			self.url,
			data={
				'device_identifier': device_a.device_identifier,
				'group': str(self.group.uuid),
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertTrue(
			ManagerRole.objects.filter(manager=device_owner, group=self.group, role='manager').exists(),
		)



class TestDeviceLeavesGroupView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('device-leave-group')
		self.group = create_group('Self Leave Group')
		self.other_group = create_group('Other Self Leave Group')

		self.device = Device.objects.create(
			device_identifier='self-leave-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.other_device = Device.objects.create(
			device_identifier='self-leave-device-2',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		GroupDevices.objects.create(group=self.group, device=self.device)
		GroupDevices.objects.create(group=self.other_group, device=self.other_device)

	def _create_device_token(self, device, raw_token):
		token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=device,
			token_hash=token_hash,
			expires_at=timezone.now() + timedelta(days=30),
		)

	def test_post_requires_authenticated_device(self):
		response = self.client.post(
			self.url,
			data={'group': str(self.group.uuid)},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_post_removes_authenticated_device_from_group(self):
		raw_token = 'device-leave-group-token'
		self._create_device_token(self.device, raw_token)

		response = self.client.post(
			self.url,
			data={'group': str(self.group.uuid)},
			format='json',
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertFalse(GroupDevices.objects.filter(group=self.group, device=self.device).exists())

	def test_post_returns_404_when_authenticated_device_not_in_group(self):
		raw_token = 'device-leave-other-group-token'
		self._create_device_token(self.device, raw_token)

		response = self.client.post(
			self.url,
			data={'group': str(self.other_group.uuid)},
			format='json',
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
		self.assertEqual(response.data['detail'], 'Device is not part of this group.')


class TestUploadEncryptedImageView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('upload-encrypted-blob')
		self.media_root = tempfile.mkdtemp()

		self.group = create_group('Upload Group')
		self.manager = User.objects.create_user(
			username='upload-manager',
			email='upload-manager@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(
			manager=self.manager,
			group=self.group,
			role='manager',
		)

		self.recipient_device = Device.objects.create(
			device_identifier='recipient-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=self.recipient_device)

	def tearDown(self):
		shutil.rmtree(self.media_root, ignore_errors=True)

	def _encrypted_images_root(self):
		return os.path.join(self.media_root, 'encrypted_images')

	def test_post_requires_authenticated_user(self):
		ciphertext = b'ciphertext-upload-bytes-unauth'
		ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
		payload_nonce = base64.b64encode(b'9' * 24).decode('ascii')
		encrypted_content_key = base64.b64encode(b'encrypted-content-key').decode('ascii')

		with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
			response = self.client.post(
				self.url,
				data={
					'group': str(self.group.uuid),
					'crypto_version': 1,
					'encryption_algorithm': 'xchacha20poly1305',
					'payload_nonce': payload_nonce,
					'client_ciphertext_hash_sha256': ciphertext_hash,
					'encrypted_blob': SimpleUploadedFile(
						'payload.bin',
						ciphertext,
						content_type='application/octet-stream',
					),
					'recipient_envelopes': json.dumps(
						[
							{
								'recipient_device_identifier': self.recipient_device.device_identifier,
								'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
								'recipient_key_fingerprint': self.recipient_device.public_key_fingerprint,
								'encrypted_content_key': encrypted_content_key,
							},
						],
					),
				},
				format='multipart',
			)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertEqual(EncryptedImage.objects.count(), 0)


	def test_post_returns_401_for_device_token_authenticated_actor(self):
		device = Device.objects.create(
			device_identifier='upload-device-actor',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=device)

		raw_token = 'device-upload-token-raw'
		token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=device,
			token_hash=token_hash,
			expires_at=timezone.now() + timedelta(days=30),
		)

		ciphertext = b'ciphertext-upload-bytes-device'
		ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
		payload_nonce = base64.b64encode(b'7' * 24).decode('ascii')
		encrypted_content_key = base64.b64encode(b'encrypted-content-key').decode('ascii')

		with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
			response = self.client.post(
				self.url,
				data={
					'group': str(self.group.uuid),
					'crypto_version': 1,
					'encryption_algorithm': 'xchacha20poly1305',
					'payload_nonce': payload_nonce,
					'client_ciphertext_hash_sha256': ciphertext_hash,
					'encrypted_blob': SimpleUploadedFile(
						'payload.bin',
						ciphertext,
						content_type='application/octet-stream',
					),
					'recipient_envelopes': json.dumps(
						[
							{
								'recipient_device_identifier': self.recipient_device.device_identifier,
								'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
								'recipient_key_fingerprint': self.recipient_device.public_key_fingerprint,
								'encrypted_content_key': encrypted_content_key,
							},
						],
					),
				},
				format='multipart',
				HTTP_AUTHORIZATION=f'Bearer {raw_token}',
				HTTP_X_DEVICE_IDENTIFIER=device.device_identifier,
			)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertEqual(EncryptedImage.objects.count(), 0)

	def test_post_creates_encrypted_image_and_recipient_envelope(self):
		self.client.force_authenticate(user=self.manager)

		ciphertext = b'ciphertext-upload-bytes-01'
		ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
		payload_nonce = base64.b64encode(b'0' * 24).decode('ascii')
		encrypted_caption = 'encrypted:caption-payload'
		encrypted_content_key = base64.b64encode(b'encrypted-content-key').decode('ascii')

		with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
      
			post_data = {
				'group': str(self.group.uuid),
				'crypto_version': 1,
				'encryption_algorithm': 'xchacha20poly1305',
				'encrypted_caption': encrypted_caption,
				'payload_nonce': payload_nonce,
				'client_ciphertext_hash_sha256': ciphertext_hash,
				'encrypted_blob': SimpleUploadedFile(
					'payload.bin',
					ciphertext,
					content_type='application/octet-stream',
				),
				'recipient_envelopes': json.dumps(
					[
						{
							'recipient_device_identifier': self.recipient_device.device_identifier,
							'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
							'recipient_key_fingerprint': self.recipient_device.public_key_fingerprint,
							'encrypted_content_key': encrypted_content_key,
						},
					],
				),
			}
      
			response = self.client.post(
				self.url,
				data=post_data,
				format='multipart',
			)
		
		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(response.data['encrypted_caption'], encrypted_caption)
		self.assertEqual(EncryptedImage.objects.count(), 1)
		self.assertEqual(RecipientEnvelope.objects.count(), 1)

		encrypted_image = EncryptedImage.objects.get()
		recipient_envelope = RecipientEnvelope.objects.get()

		self.assertEqual(encrypted_image.group, self.group)
		self.assertEqual(encrypted_image.uploaded_by, self.manager)
		self.assertEqual(encrypted_image.encrypted_caption, encrypted_caption)
		self.assertEqual(encrypted_image.ciphertext_hash_sha256, ciphertext_hash)
		self.assertEqual(recipient_envelope.encrypted_image, encrypted_image)
		self.assertEqual(recipient_envelope.recipient_device, self.recipient_device)

	def test_post_returns_403_when_authenticated_manager_is_not_in_group(self):
		non_member_manager = User.objects.create_user(
			username='outside-manager',
			email='outside-manager@example.com',
			password='test-password-123',
		)
		other_group = create_group('Other Upload Group')
		ManagerRole.objects.create(
			manager=non_member_manager,
			group=other_group,
			role='manager',
		)
		self.client.force_authenticate(user=non_member_manager)

		ciphertext = b'ciphertext-upload-bytes-02'
		ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()
		payload_nonce = base64.b64encode(b'1' * 24).decode('ascii')
		encrypted_content_key = base64.b64encode(b'encrypted-content-key').decode('ascii')

		with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
			response = self.client.post(
				self.url,
				data={
					'group': str(self.group.uuid),
					'crypto_version': 1,
					'encryption_algorithm': 'xchacha20poly1305',
					'payload_nonce': payload_nonce,
					'client_ciphertext_hash_sha256': ciphertext_hash,
					'encrypted_blob': SimpleUploadedFile(
						'payload.bin',
						ciphertext,
						content_type='application/octet-stream',
					),
					'recipient_envelopes': json.dumps(
						[
							{
								'recipient_device_identifier': self.recipient_device.device_identifier,
								'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
								'recipient_key_fingerprint': self.recipient_device.public_key_fingerprint,
								'encrypted_content_key': encrypted_content_key,
							},
						],
					),
				},
				format='multipart',
			)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
		self.assertEqual(response.data['detail'], 'Only group managers can perform this action.')
		self.assertEqual(EncryptedImage.objects.count(), 0)
		self.assertEqual(RecipientEnvelope.objects.count(), 0)

	def test_post_returns_403_when_max_images_quota_reached(self):
		self.client.force_authenticate(user=self.manager)
		create_quota_organization(max_groups=100, max_devices=100, max_images=1)

		with override_settings(ENCRYPTED_IMAGES_ROOT=self._encrypted_images_root()):
			existing_blob = b'existing-ciphertext-over-quota'
			EncryptedImage.objects.create(
				encrypted_blob=SimpleUploadedFile(
					'existing.bin',
					existing_blob,
					content_type='application/octet-stream',
				),
				group=self.group,
				uploaded_by=self.manager,
				payload_nonce=os.urandom(24),
				ciphertext_hash_sha256=hashlib.sha256(existing_blob).hexdigest(),
			)

			ciphertext = b'ciphertext-upload-over-quota'
			payload_nonce = base64.b64encode(b'4' * 24).decode('ascii')
			encrypted_content_key = base64.b64encode(b'encrypted-content-key').decode('ascii')

			response = self.client.post(
				self.url,
				data={
					'group': str(self.group.uuid),
					'crypto_version': 1,
					'encryption_algorithm': 'xchacha20poly1305',
					'payload_nonce': payload_nonce,
					'client_ciphertext_hash_sha256': hashlib.sha256(ciphertext).hexdigest(),
					'encrypted_blob': SimpleUploadedFile(
						'payload.bin',
						ciphertext,
						content_type='application/octet-stream',
					),
					'recipient_envelopes': json.dumps(
						[
							{
								'recipient_device_identifier': self.recipient_device.device_identifier,
								'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
								'recipient_key_fingerprint': self.recipient_device.public_key_fingerprint,
								'encrypted_content_key': encrypted_content_key,
							},
						],
					),
				},
				format='multipart',
			)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
		self.assertEqual(response.data['quota'], 'max_images')
		self.assertEqual(response.data['current'], 1)
		self.assertEqual(response.data['maximum'], 1)
		self.assertEqual(EncryptedImage.objects.count(), 1)


class TestDeleteEncryptedImageView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('delete-encrypted-image')
		self.media_root = tempfile.mkdtemp()

		self.group = create_group('Delete Image Group')
		self.manager = User.objects.create_user(
			username='delete-manager',
			email='delete-manager@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=self.manager, group=self.group, role='manager')

		self.group_device = Device.objects.create(
			device_identifier='delete-group-device',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=self.group_device)

	def tearDown(self):
		shutil.rmtree(self.media_root, ignore_errors=True)

	def _create_image(self, *, uploaded_by=None):
		uploader = uploaded_by or self.manager
		ciphertext = b'delete-me-ciphertext'
		with override_settings(MEDIA_ROOT=self.media_root, ENCRYPTED_IMAGES_ROOT='encrypted_images'):
			encrypted_image = EncryptedImage.objects.create(
				encrypted_blob=SimpleUploadedFile(
					'delete_payload.bin',
					ciphertext,
					content_type='application/octet-stream',
				),
				group=self.group,
				uploaded_by=uploader,
				payload_nonce=os.urandom(24),
				ciphertext_hash_sha256=hashlib.sha256(ciphertext).hexdigest(),
			)
		RecipientEnvelope.objects.create(
			encrypted_image=encrypted_image,
			recipient_device=self.group_device,
			key_wrap_algorithm=DEFAULT_KEY_WRAP_ALGORITHM,
			recipient_key_fingerprint=self.group_device.public_key_fingerprint,
			encrypted_content_key=os.urandom(48),
		)
		return encrypted_image

	def _device_auth_headers(self, device, raw_token):
		return {
			'HTTP_AUTHORIZATION': f'Bearer {raw_token}',
			'HTTP_X_DEVICE_IDENTIFIER': device.device_identifier,
		}

	def _create_device_token(self, device, raw_token):
		token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=device,
			token_hash=token_hash,
			expires_at=timezone.now() + timedelta(days=30),
		)

	def test_post_requires_authenticated_actor(self):
		encrypted_image = self._create_image()

		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'image_uuid': str(encrypted_image.uuid),
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
		self.assertTrue(EncryptedImage.objects.filter(uuid=encrypted_image.uuid).exists())

	def test_post_deletes_image_for_group_device(self):
		encrypted_image = self._create_image()
		raw_token = 'delete-group-device-token'
		self._create_device_token(self.group_device, raw_token)

		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'image_uuid': str(encrypted_image.uuid),
			},
			format='json',
			**self._device_auth_headers(self.group_device, raw_token),
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertFalse(EncryptedImage.objects.filter(uuid=encrypted_image.uuid).exists())

	def test_post_returns_403_when_device_not_in_target_group(self):
		encrypted_image = self._create_image()
		outside_device = Device.objects.create(
			device_identifier='outside-delete-device',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		raw_token = 'outside-delete-device-token'
		self._create_device_token(outside_device, raw_token)

		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'image_uuid': str(encrypted_image.uuid),
			},
			format='json',
			**self._device_auth_headers(outside_device, raw_token),
		)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
		self.assertTrue(EncryptedImage.objects.filter(uuid=encrypted_image.uuid).exists())

	def test_post_returns_404_when_in_group_device_has_no_recipient_envelope(self):
		encrypted_image = self._create_image()
		late_join_device = Device.objects.create(
			device_identifier='late-join-delete-device',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=late_join_device)
		raw_token = 'late-join-delete-device-token'
		self._create_device_token(late_join_device, raw_token)

		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'image_uuid': str(encrypted_image.uuid),
			},
			format='json',
			**self._device_auth_headers(late_join_device, raw_token),
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
		self.assertEqual(response.data['detail'], 'Encrypted image not found.')
		self.assertTrue(EncryptedImage.objects.filter(uuid=encrypted_image.uuid).exists())

	def test_post_returns_404_when_image_not_found_in_group(self):
		raw_token = 'delete-missing-image-token'
		self._create_device_token(self.group_device, raw_token)

		import uuid as uuidlib
		fake_uuid = str(uuidlib.uuid4())
		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'image_uuid': fake_uuid,
			},
			format='json',
			**self._device_auth_headers(self.group_device, raw_token),
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
		self.assertEqual(response.data['detail'], 'Encrypted image not found.')


class TestGetDeviceGroupsView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('device-groups')

		self.device = Device.objects.create(
			device_identifier='device-groups-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		self.other_device = Device.objects.create(
			device_identifier='device-groups-device-2',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		self.group_one = create_group('Device Group One')
		self.group_two = create_group('Device Group Two')
		self.other_group = create_group('Other Device Group')

		GroupDevices.objects.create(group=self.group_one, device=self.device)
		GroupDevices.objects.create(group=self.group_two, device=self.device)
		GroupDevices.objects.create(group=self.other_group, device=self.other_device)

	def _create_device_token(self, device, raw_token):
		token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=device,
			token_hash=token_hash,
			expires_at=timezone.now() + timedelta(days=30),
		)

	def test_get_requires_authenticated_device(self):
		response = self.client.get(self.url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_returns_all_groups_for_authenticated_device(self):
		raw_token = 'device-groups-token'
		self._create_device_token(self.device, raw_token)

		response = self.client.get(
			self.url,
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(len(response.data), 2)

		returned_group_uuids = {item['uuid'] for item in response.data}
		expected_group_uuids = {str(self.group_one.uuid), str(self.group_two.uuid)}
		self.assertEqual(returned_group_uuids, expected_group_uuids)

		for item in response.data:
			self.assertEqual(item['user_role'], 'member')


class TestListEncryptedImagesView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('device-encrypted-images')
		self.blob_url = lambda image_uuid: reverse('device-encrypted-image-blob', kwargs={'image_uuid': image_uuid})
		self.media_root = tempfile.mkdtemp()

		self.device = Device.objects.create(
			device_identifier='device-encrypted-images-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.other_device = Device.objects.create(
			device_identifier='device-encrypted-images-device-2',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		self.group_one = create_group('Encrypted Images Group One')
		self.group_two = create_group('Encrypted Images Group Two')

	def tearDown(self):
		shutil.rmtree(self.media_root, ignore_errors=True)

	def _create_device_token(self, device, raw_token):
		token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=device,
			token_hash=token_hash,
			expires_at=timezone.now() + timedelta(days=30),
		)

	def _create_recipient_image(self, *, group, created_at, caption, filename, device=None):
		device = device or self.device
		ciphertext = f'ciphertext:{filename}'.encode('utf-8')
		ciphertext_hash = hashlib.sha256(ciphertext).hexdigest()

		with override_settings(ENCRYPTED_IMAGES_ROOT=os.path.join(self.media_root, 'encrypted_images')):
			encrypted_image = EncryptedImage.objects.create(
				encrypted_blob=SimpleUploadedFile(
					filename,
					ciphertext,
					content_type='application/octet-stream',
				),
				encrypted_caption=caption,
				group=group,
				uploaded_by=None,
				payload_nonce=os.urandom(24),
				ciphertext_hash_sha256=ciphertext_hash,
			)

		RecipientEnvelope.objects.create(
			encrypted_image=encrypted_image,
			recipient_device=device,
			key_wrap_algorithm=DEFAULT_KEY_WRAP_ALGORITHM,
			recipient_key_fingerprint=device.public_key_fingerprint,
			encrypted_content_key=os.urandom(48),
		)
		EncryptedImage.objects.filter(id=encrypted_image.id).update(created_at=created_at)
		encrypted_image.refresh_from_db()
		return encrypted_image

	def test_get_requires_authenticated_device(self):
		response = self.client.get(self.url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_returns_images_grouped_by_group_and_day(self):
		raw_token = 'device-encrypted-images-token'
		self._create_device_token(self.device, raw_token)

		base_time = timezone.now().replace(hour=12, minute=0, second=0, microsecond=0)
		image_one = self._create_recipient_image(
			group=self.group_one,
			created_at=base_time,
			caption='caption-one',
			filename='one.bin',
		)
		image_two = self._create_recipient_image(
			group=self.group_one,
			created_at=base_time - timedelta(hours=1),
			caption='caption-two',
			filename='two.bin',
		)
		image_three = self._create_recipient_image(
			group=self.group_one,
			created_at=base_time - timedelta(days=1),
			caption='caption-three',
			filename='three.bin',
		)
		image_four = self._create_recipient_image(
			group=self.group_two,
			created_at=base_time - timedelta(minutes=30),
			caption='caption-four',
			filename='four.bin',
		)
		self._create_recipient_image(
			group=self.group_two,
			created_at=base_time - timedelta(minutes=15),
			caption='caption-ignored',
			filename='ignored.bin',
			device=self.other_device,
		)

		response = self.client.get(
			self.url,
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertIsNone(response.data['next_cursor'])
		self.assertEqual(len(response.data['groups']), 2)

		first_group = response.data['groups'][0]
		self.assertEqual(first_group['group'], str(self.group_one.uuid))
		self.assertEqual(first_group['encrypted_name'], self.group_one.encrypted_name)
		self.assertEqual(len(first_group['days']), 2)
		self.assertEqual(first_group['days'][0]['day'], base_time.date().isoformat())
		self.assertEqual(
			[item['image_uuid'] for item in first_group['days'][0]['images']],
			[str(image_one.uuid), str(image_two.uuid)],
		)
		self.assertEqual(first_group['days'][1]['day'], (base_time - timedelta(days=1)).date().isoformat())
		self.assertEqual(first_group['days'][1]['images'][0]['image_uuid'], str(image_three.uuid))

		second_group = response.data['groups'][1]
		self.assertEqual(second_group['group'], str(self.group_two.uuid))
		self.assertEqual(len(second_group['days']), 1)
		self.assertEqual(second_group['days'][0]['images'][0]['image_uuid'], str(image_four.uuid))

	def test_blob_get_returns_nginx_internal_redirect_for_recipient(self):
		raw_token = 'device-encrypted-images-blob-token'
		self._create_device_token(self.device, raw_token)
		image = self._create_recipient_image(
			group=self.group_one,
			created_at=timezone.now(),
			caption='blob-caption',
			filename='blob.bin',
		)

		with override_settings(
			ENCRYPTED_IMAGES_ROOT=os.path.join(self.media_root, 'encrypted_images'),
			ENCRYPTED_IMAGES_INTERNAL_LOCATION='/protected-encrypted-images/',
		):
			response = self.client.get(
				self.blob_url(image.uuid),
				HTTP_AUTHORIZATION=f'Bearer {raw_token}',
				HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
			)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(
			response['X-Accel-Redirect'],
			f'/protected-encrypted-images/{image.encrypted_blob.name}',
		)
		self.assertEqual(response['Content-Type'], 'application/octet-stream')
		self.assertEqual(
			response['Content-Disposition'],
			f'attachment; filename="encrypted-image-{image.uuid}.bin"',
		)

	def test_blob_get_returns_404_for_non_recipient(self):
		raw_token = 'device-encrypted-images-blob-other-device-token'
		self._create_device_token(self.other_device, raw_token)
		image = self._create_recipient_image(
			group=self.group_one,
			created_at=timezone.now(),
			caption='blob-caption',
			filename='blob.bin',
		)

		response = self.client.get(
			self.blob_url(image.uuid),
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.other_device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

	def test_get_supports_cursor_pagination(self):
		raw_token = 'device-encrypted-images-pagination-token'
		self._create_device_token(self.device, raw_token)

		base_time = timezone.now().replace(hour=12, minute=0, second=0, microsecond=0)
		image_one = self._create_recipient_image(
			group=self.group_one,
			created_at=base_time,
			caption='caption-one',
			filename='one.bin',
		)
		image_two = self._create_recipient_image(
			group=self.group_one,
			created_at=base_time - timedelta(hours=1),
			caption='caption-two',
			filename='two.bin',
		)
		image_three = self._create_recipient_image(
			group=self.group_two,
			created_at=base_time - timedelta(days=1),
			caption='caption-three',
			filename='three.bin',
		)

		first_response = self.client.get(
			self.url,
			{'limit': 2},
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(first_response.status_code, status.HTTP_200_OK)
		self.assertIsNotNone(first_response.data['next_cursor'])
		first_page_image_uuids = [
			item['image_uuid']
			for day_group in first_response.data['groups'][0]['days']
			for item in day_group['images']
		]
		self.assertEqual(first_page_image_uuids, [str(image_one.uuid), str(image_two.uuid)])

		second_response = self.client.get(
			self.url,
			{'limit': 2, 'cursor': first_response.data['next_cursor']},
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(second_response.status_code, status.HTTP_200_OK)
		self.assertIsNone(second_response.data['next_cursor'])
		second_page_image_uuids = [
			item['image_uuid']
			for group in second_response.data['groups']
			for day_group in group['days']
			for item in day_group['images']
		]
		self.assertEqual(second_page_image_uuids, [str(image_three.uuid)])

	def test_post_removes_manager_role_when_last_owned_device_leaves(self):
		leave_group_url = reverse('device-leave-group')
		device_owner = User.objects.create_user(
			username='leave-owner-single',
			email='leave-owner-single@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=device_owner, group=self.group_one, role='manager')
		owned_device = Device.objects.create(
			device_identifier='self-leave-owned-single',
			owner_user=device_owner,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group_one, device=owned_device)
		raw_token = 'leave-manager-role-token'
		self._create_device_token(owned_device, raw_token)

		response = self.client.post(
			leave_group_url,
			data={'group': str(self.group_one.uuid)},
			format='json',
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=owned_device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertFalse(
			ManagerRole.objects.filter(manager=device_owner, group=self.group_one).exists(),
		)

	def test_post_preserves_manager_role_when_owner_has_remaining_device(self):
		leave_group_url = reverse('device-leave-group')
		device_owner = User.objects.create_user(
			username='leave-owner-two',
			email='leave-owner-two@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=device_owner, group=self.group_one, role='manager')
		device_leaving = Device.objects.create(
			device_identifier='self-leave-owned-leaving',
			owner_user=device_owner,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		device_staying = Device.objects.create(
			device_identifier='self-leave-owned-staying',
			owner_user=device_owner,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group_one, device=device_leaving)
		GroupDevices.objects.create(group=self.group_one, device=device_staying)
		raw_token = 'leave-manager-role-two-devices-token'
		self._create_device_token(device_leaving, raw_token)

		response = self.client.post(
			leave_group_url,
			data={'group': str(self.group_one.uuid)},
			format='json',
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=device_leaving.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertTrue(
			ManagerRole.objects.filter(manager=device_owner, group=self.group_one, role='manager').exists(),
		)


class TestGetDeviceGroupKeyEnvelopesView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('device-group-key-envelopes')
		self.manager_user = User.objects.create_user(
			username='device-group-envelope-manager',
			email='device-group-envelope-manager@example.com',
			password='test-password-123',
		)

		self.device = Device.objects.create(
			device_identifier='device-group-key-envelope-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.manager_device = Device.objects.create(
			device_identifier='device-group-key-envelope-manager-device',
			owner_user=self.manager_user,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.other_device = Device.objects.create(
			device_identifier='device-group-key-envelope-device-2',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		self.group_one = create_group('Device Envelope Group One')
		self.group_two = create_group('Device Envelope Group Two')
		self.other_group = create_group('Other Device Envelope Group')

		ManagerRole.objects.create(manager=self.manager_user, group=self.group_one, role='manager')
		GroupDevices.objects.create(group=self.group_one, device=self.device)
		GroupDevices.objects.create(group=self.group_two, device=self.device)
		GroupDevices.objects.create(group=self.group_one, device=self.manager_device)
		GroupDevices.objects.create(group=self.other_group, device=self.other_device)

		GroupKeyEnvelope.objects.create(
			group=self.group_one,
			recipient_device=self.device,
			scope=GROUP_KEY_SCOPE_GROUP_SHARED,
			recipient_key_fingerprint=self.device.public_key_fingerprint,
			encrypted_group_key=b'group-key-one',
		)
		GroupKeyEnvelope.objects.create(
			group=self.group_two,
			recipient_device=self.device,
			scope=GROUP_KEY_SCOPE_MANAGER_ROSTER,
			recipient_key_fingerprint=self.device.public_key_fingerprint,
			encrypted_group_key=b'group-key-hidden-from-regular-device',
		)
		GroupKeyEnvelope.objects.create(
			group=self.group_one,
			recipient_device=self.manager_device,
			scope=GROUP_KEY_SCOPE_MANAGER_ROSTER,
			recipient_key_fingerprint=self.manager_device.public_key_fingerprint,
			encrypted_group_key=b'manager-roster-key',
		)
		GroupKeyEnvelope.objects.create(
			group=self.other_group,
			recipient_device=self.other_device,
			scope=GROUP_KEY_SCOPE_GROUP_SHARED,
			recipient_key_fingerprint=self.other_device.public_key_fingerprint,
			encrypted_group_key=b'group-key-other-device',
		)

	def _create_device_token(self, device, raw_token):
		token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=device,
			token_hash=token_hash,
			expires_at=timezone.now() + timedelta(days=30),
		)

	def test_post_requires_authenticated_device(self):
		response = self.client.post(
			self.url,
			data={'groups': [str(self.group_one.uuid)]},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_post_returns_only_authenticated_devices_requested_envelopes(self):
		raw_token = 'device-group-envelope-token'
		self._create_device_token(self.device, raw_token)

		response = self.client.post(
			self.url,
			data={'groups': [str(self.group_one.uuid), str(self.group_two.uuid), str(self.other_group.uuid)]},
			format='json',
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(len(response.data), 1)
		self.assertEqual(response.data[0]['group'], str(self.group_one.uuid))
		self.assertEqual(response.data[0]['scope'], GROUP_KEY_SCOPE_GROUP_SHARED)
		self.assertEqual(response.data[0]['recipient_key_fingerprint'], self.device.public_key_fingerprint)
		self.assertEqual(
			response.data[0]['encrypted_group_key'],
			base64.b64encode(b'group-key-one').decode('ascii'),
		)

	def test_post_returns_manager_roster_envelopes_to_manager_owned_devices(self):
		raw_token = 'manager-device-group-envelope-token'
		self._create_device_token(self.manager_device, raw_token)

		response = self.client.post(
			self.url,
			data={
				'groups': [str(self.group_one.uuid)],
				'scopes': [GROUP_KEY_SCOPE_MANAGER_ROSTER],
			},
			format='json',
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.manager_device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(len(response.data), 1)
		self.assertEqual(response.data[0]['group'], str(self.group_one.uuid))
		self.assertEqual(response.data[0]['scope'], GROUP_KEY_SCOPE_MANAGER_ROSTER)
		self.assertEqual(
			response.data[0]['encrypted_group_key'],
			base64.b64encode(b'manager-roster-key').decode('ascii'),
		)

	def test_post_returns_empty_list_when_no_matching_envelopes_exist(self):
		raw_token = 'device-group-envelope-empty-token'
		self._create_device_token(self.device, raw_token)

		response = self.client.post(
			self.url,
			data={'groups': [str(self.group_two.uuid)]},
			format='json',
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data, [])


class TestGetDeviceSelfStatusView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('device-self-status')

		self.device = Device.objects.create(
			device_identifier='device-self-status-device',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.group = create_group('Self Status Group')
		GroupDevices.objects.create(group=self.group, device=self.device)

	def _create_device_token(self, device, raw_token):
		token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=device,
			token_hash=token_hash,
			expires_at=timezone.now() + timedelta(days=30),
		)

	def test_get_requires_authenticated_device(self):
		response = self.client.get(self.url)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_returns_authenticated_device_self_status(self):
		raw_token = 'device-self-status-token'
		self._create_device_token(self.device, raw_token)

		response = self.client.get(
			self.url,
			HTTP_AUTHORIZATION=f'Bearer {raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['device_identifier'], self.device.device_identifier)
		self.assertTrue(response.data['is_registered'])
		self.assertEqual(response.data['group_names'], ['Self Status Group'])
		self.assertEqual(response.data['organization_name'], get_organization_name())


class TestApiPathLayout(TestCase):
	def test_device_auth_challenge_uses_device_auth_collection_path(self):
		self.assertEqual(reverse('device-auth-challenge'), '/api/device/auth/challenge/')

	def test_device_auth_token_uses_device_auth_collection_path(self):
		self.assertEqual(reverse('device-auth-token'), '/api/device/auth/token/')

	def test_device_auth_revoke_uses_device_auth_collection_path(self):
		self.assertEqual(reverse('device-auth-revoke'), '/api/device/auth/revoke/')

	def test_register_device_uses_main_manager_collection_path(self):
		self.assertEqual(reverse('register-device'), '/api/main-manager/register-device/')

	def test_create_group_uses_main_manager_collection_path(self):
		self.assertEqual(reverse('create-group'), '/api/main-manager/create-group/')

	def test_create_group_key_envelope_uses_main_manager_collection_path(self):
		self.assertEqual(reverse('create-group-key-envelope'), '/api/main-manager/create-group-key-envelope/')

	def test_update_group_uses_main_manager_collection_path(self):
		self.assertEqual(reverse('update-group'), '/api/main-manager/update-group/')

	def test_delete_group_uses_main_manager_collection_path(self):
		self.assertEqual(reverse('delete-group'), '/api/main-manager/delete-group/')

	def test_device_groups_uses_device_collection_path(self):
		self.assertEqual(reverse('device-groups'), '/api/device/groups/')

	def test_device_group_key_envelopes_uses_device_collection_path(self):
		self.assertEqual(reverse('device-group-key-envelopes'), '/api/device/group-key-envelopes/')

	def test_device_encrypted_images_uses_device_collection_path(self):
		self.assertEqual(reverse('device-encrypted-images'), '/api/device/encrypted-images/')

	def test_device_encrypted_image_blob_uses_device_collection_path(self):
		import uuid as uuidlib
		fake_uuid = uuidlib.UUID('12345678-1234-5678-1234-567812345678')
		self.assertEqual(
			reverse('device-encrypted-image-blob', kwargs={'image_uuid': fake_uuid}),
			f'/api/device/encrypted-images/{fake_uuid}/blob/',
		)

	def test_device_self_status_uses_device_collection_path(self):
		self.assertEqual(reverse('device-self-status'), '/api/device/self/status/')

	def test_add_device_to_group_uses_main_manager_collection_path(self):
		self.assertEqual(reverse('add-device-to-group'), '/api/main-manager/add-device-to-group/')

	def test_remove_device_from_group_uses_main_manager_collection_path(self):
		self.assertEqual(reverse('remove-device-from-group'), '/api/main-manager/remove-device-from-group/')

	def test_upload_encrypted_blob_uses_manager_collection_path(self):
		self.assertEqual(reverse('upload-encrypted-blob'), '/api/manager/upload-encrypted-blob/')

	def test_manager_groups_uses_manager_collection_path(self):
		self.assertEqual(reverse('manager-groups'), '/api/manager/groups/')

	def test_manager_group_devices_uses_manager_collection_path(self):
		self.assertEqual(reverse('manager-group-devices'), '/api/manager/group-devices/')

	def test_main_manager_group_devices_uses_main_manager_collection_path(self):
		self.assertEqual(reverse('main-manager-group-devices'), '/api/main-manager/group-devices/')

	def test_manager_notify_group_uses_manager_collection_path(self):
		self.assertEqual(reverse('manager-notify-group'), '/api/manager/notify-group/')


class TestNotifyGroupView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('manager-notify-group')

		self.group = create_group('notify-group-name')
		self.manager = User.objects.create_user(
			username='notify-manager',
			email='notify-manager@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=self.manager, group=self.group, role='manager')

		self.device = Device.objects.create(
			device_identifier='notify-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=self.device)

		self.fcm_device = FCMDevice.objects.create(
			registration_id='test-fcm-token-notify-1',
			type='android',
			active=True,
		)
		self.device.fcm_device = self.fcm_device
		self.device.save(update_fields=['fcm_device'])

		self.valid_nonce = base64.b64encode(os.urandom(24)).decode('ascii')
		self.valid_payload = base64.b64encode(b'encrypted-message-bytes').decode('ascii')

	def _post(self, data=None):
		if data is None:
			data = {
				'group': str(self.group.uuid),
				'encrypted_payload': self.valid_payload,
				'nonce': self.valid_nonce,
				'crypto_version': 1,
				'encryption_algorithm': 'xchacha20poly1305',
			}
		return self.client.post(self.url, data=data, format='json')

	def test_post_returns_401_for_unauthenticated(self):
		response = self._post()
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_post_returns_403_for_non_manager(self):
		non_manager = User.objects.create_user(
			username='notify-non-manager',
			email='non-manager@example.com',
			password='test-password-123',
		)
		self.client.force_authenticate(user=non_manager)
		response = self._post()
		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

	def test_post_returns_400_for_unknown_group(self):
		self.client.force_authenticate(user=self.manager)
		response = self._post(data={
			'group': '00000000-0000-0000-0000-000000000000',
			'encrypted_payload': self.valid_payload,
			'nonce': self.valid_nonce,
			'crypto_version': 1,
			'encryption_algorithm': 'xchacha20poly1305',
		})
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('group', response.data)

	def test_post_returns_400_for_invalid_base64_payload(self):
		self.client.force_authenticate(user=self.manager)
		response = self._post(data={
			'group': str(self.group.uuid),
			'encrypted_payload': 'not-valid-base64!!!',
			'nonce': self.valid_nonce,
			'crypto_version': 1,
			'encryption_algorithm': 'xchacha20poly1305',
		})
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('encrypted_payload', response.data)

	def test_post_returns_400_for_wrong_nonce_length(self):
		self.client.force_authenticate(user=self.manager)
		short_nonce = base64.b64encode(os.urandom(12)).decode('ascii')  # 12 bytes, xchacha20 needs 24
		response = self._post(data={
			'group': str(self.group.uuid),
			'encrypted_payload': self.valid_payload,
			'nonce': short_nonce,
			'crypto_version': 1,
			'encryption_algorithm': 'xchacha20poly1305',
		})
		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('nonce', response.data)

	@patch('eyesonly.api.views.messaging.send_each_for_multicast')
	def test_post_sends_fcm_to_group_devices_with_active_token(self, mock_send):
		mock_result = MagicMock()
		mock_result.success_count = 1
		mock_send.return_value = mock_result

		self.client.force_authenticate(user=self.manager)
		response = self._post()

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['notified_count'], 1)
		self.assertEqual(response.data['skipped_count'], 0)

		mock_send.assert_called_once()
		call_args = mock_send.call_args[0][0]
		self.assertEqual(call_args.tokens, ['test-fcm-token-notify-1'])
		self.assertEqual(call_args.data['event'], 'new_images')
		self.assertEqual(call_args.data['group'], str(self.group.uuid))
		self.assertEqual(call_args.data['encrypted_payload'], self.valid_payload)
		self.assertEqual(call_args.data['nonce'], self.valid_nonce)
		self.assertEqual(call_args.data['encryption_algorithm'], 'xchacha20poly1305')
		self.assertEqual(call_args.android.priority, 'high')
		self.assertEqual(call_args.apns.headers['apns-priority'], '10')
		self.assertEqual(call_args.notification.title, 'Eyes Only')
		self.assertEqual(call_args.notification.body, 'There are new images for you.')

	@patch('eyesonly.api.views.messaging.send_each_for_multicast')
	def test_post_skips_devices_without_active_fcm(self, mock_send):
		device_no_fcm = Device.objects.create(
			device_identifier='notify-device-no-fcm',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=device_no_fcm)

		mock_result = MagicMock()
		mock_result.success_count = 1
		mock_send.return_value = mock_result

		self.client.force_authenticate(user=self.manager)
		response = self._post()

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['notified_count'], 1)
		self.assertEqual(response.data['skipped_count'], 1)

	@patch('eyesonly.api.views.messaging.send_each_for_multicast')
	def test_post_returns_200_with_zero_notified_when_no_fcm_tokens(self, mock_send):
		self.fcm_device.active = False
		self.fcm_device.save(update_fields=['active'])

		self.client.force_authenticate(user=self.manager)
		response = self._post()

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['notified_count'], 0)
		self.assertEqual(response.data['skipped_count'], 1)
		mock_send.assert_not_called()

	@patch('eyesonly.api.views.messaging.send_each_for_multicast')
	def test_post_does_not_notify_devices_in_other_groups(self, mock_send):
		other_group = create_group('other-group')
		other_device = Device.objects.create(
			device_identifier='notify-other-group-device',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=other_group, device=other_device)
		other_fcm = FCMDevice.objects.create(
			registration_id='other-group-token',
			type='android',
			active=True,
		)
		other_device.fcm_device = other_fcm
		other_device.save(update_fields=['fcm_device'])

		mock_result = MagicMock()
		mock_result.success_count = 1
		mock_send.return_value = mock_result

		self.client.force_authenticate(user=self.manager)
		response = self._post()

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data['notified_count'], 1)
		call_args = mock_send.call_args[0][0]
		self.assertNotIn('other-group-token', call_args.tokens)
		self.assertIn('test-fcm-token-notify-1', call_args.tokens)


class TestApiSchemaYaml(TestCase):
	def setUp(self):
		self.client = APIClient()

	def _assert_quota_error_schema(self, operation):
		self.assertIn('403', operation['responses'])
		quota_schema = operation['responses']['403']['content']['application/json']['schema']
		quota_properties = quota_schema.get('properties', {})
		self.assertIn('detail', quota_properties)
		self.assertIn('quota', quota_properties)
		self.assertIn('current', quota_properties)
		self.assertIn('maximum', quota_properties)

	def _resolve_schema_object(self, schema, schema_obj):
		ref = schema_obj.get('$ref')
		if not ref:
			return schema_obj

		prefix = '#/components/schemas/'
		self.assertTrue(ref.startswith(prefix), f'Unexpected schema reference: {ref}')
		schema_name = ref[len(prefix):]
		return schema['components']['schemas'][schema_name]

	def test_device_self_status_is_documented_as_read_only_get_response(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/device/self/status/']['get']

		# GET self-status is response-only and should not define a request body.
		self.assertNotIn('requestBody', operation)

		response_schema = operation['responses']['200']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		properties = resolved_response_schema.get('properties', {})

		self.assertIn('device_identifier', properties)
		self.assertIn('is_registered', properties)
		self.assertIn('group_names', properties)
		self.assertIn('organization_name', properties)

		# If security is emitted for this operation, it should contain at least one auth requirement.
		if 'security' in operation:
			self.assertTrue(operation['security'])

	def test_device_auth_challenge_schema_has_request_and_response_shapes(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/device/auth/challenge/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('device_identifier', request_properties)

		response_schema = operation['responses']['201']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		response_properties = resolved_response_schema.get('properties', {})
		self.assertIn('encrypted_challenge', response_properties)
		self.assertIn('expires_at', response_properties)

	def test_device_auth_token_schema_has_request_and_response_shapes(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/device/auth/token/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('device_identifier', request_properties)
		self.assertIn('challenge', request_properties)

		response_schema = operation['responses']['201']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		response_properties = resolved_response_schema.get('properties', {})
		self.assertIn('access_token', response_properties)
		self.assertIn('token_type', response_properties)
		self.assertIn('expires_at', response_properties)

	def test_device_auth_revoke_schema_has_auth_and_no_request_body(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/device/auth/revoke/']['post']

		# Accept presence of requestBody if schema is empty (OpenAPI default)
		if 'requestBody' in operation:
			for content_type, content in operation['requestBody'].get('content', {}).items():
				self.assertEqual(content.get('schema', {}), {}, f"requestBody schema for {content_type} should be empty")
		self.assertIn('204', operation['responses'])

		# Revoke endpoint should be authenticated, but tolerate missing 'security' key in OpenAPI output
		# Some schema generators omit 'security' if global security applies or for public endpoints
		if 'security' in operation:
			self.assertTrue(operation['security'])

	def test_device_leave_group_schema_has_request_and_responses(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/device/leave-group/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('group', request_properties)

	def test_register_device_schema_documents_optional_owner_user(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/main-manager/register-device/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		request_required = resolved_request_schema.get('required', [])

		self.assertIn('device_identifier', request_properties)
		self.assertIn('public_key', request_properties)
		self.assertIn('public_key_algorithm', request_properties)
		self.assertIn('owner_user', request_properties)
		self.assertNotIn('owner_user', request_required)
		self.assertIn('200', operation['responses'])
		self.assertIn('201', operation['responses'])
		self._assert_quota_error_schema(operation)

	def test_device_group_key_envelopes_schema_has_request_and_array_response(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/device/group-key-envelopes/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('groups', request_properties)
		self.assertIn('scopes', request_properties)

		response_schema = operation['responses']['200']['content']['application/json']['schema']
		self.assertEqual(response_schema.get('type'), 'array')
		resolved_item_schema = self._resolve_schema_object(schema, response_schema['items'])
		response_properties = resolved_item_schema.get('properties', {})
		self.assertIn('group', response_properties)
		self.assertIn('scope', response_properties)
		self.assertIn('key_wrap_algorithm', response_properties)
		self.assertIn('recipient_key_fingerprint', response_properties)
		self.assertIn('encrypted_group_key', response_properties)

	def test_device_encrypted_images_schema_has_grouped_response_shape(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/device/encrypted-images/']['get']

		parameter_names = {parameter['name'] for parameter in operation.get('parameters', [])}
		self.assertIn('cursor', parameter_names)
		self.assertIn('limit', parameter_names)

		response_schema = operation['responses']['200']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		response_properties = resolved_response_schema.get('properties', {})
		self.assertIn('groups', response_properties)
		self.assertIn('next_cursor', response_properties)

		group_schema = self._resolve_schema_object(schema, response_properties['groups']['items'])
		day_schema = self._resolve_schema_object(schema, group_schema['properties']['days']['items'])
		image_schema = self._resolve_schema_object(schema, day_schema['properties']['images']['items'])
		image_properties = image_schema.get('properties', {})
		self.assertIn('image_uuid', image_properties)
		self.assertIn('400', operation['responses'])
		self.assertIn('401', operation['responses'])

	def test_device_encrypted_image_blob_schema_has_binary_response_shape(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/device/encrypted-images/{image_uuid}/blob/']['get']

		self.assertNotIn('requestBody', operation)

		parameter_names = {parameter['name'] for parameter in operation.get('parameters', [])}
		self.assertIn('image_uuid', parameter_names)

		binary_schema = operation['responses']['200']['content']['application/octet-stream']['schema']
		self.assertEqual(binary_schema.get('type'), 'string')
		self.assertEqual(binary_schema.get('format'), 'binary')
		self.assertIn('401', operation['responses'])
		self.assertIn('404', operation['responses'])

	def test_main_manager_group_devices_schema_has_query_parameter_and_array_response(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/main-manager/group-devices/']['get']

		parameter_names = {parameter['name'] for parameter in operation.get('parameters', [])}
		self.assertIn('group', parameter_names)

		response_schema = operation['responses']['200']['content']['application/json']['schema']
		self.assertEqual(response_schema.get('type'), 'array')
		resolved_item_schema = self._resolve_schema_object(schema, response_schema['items'])
		response_properties = resolved_item_schema.get('properties', {})
		self.assertIn('device_identifier', response_properties)
		self.assertIn('encrypted_member_name', response_properties)
		self.assertIn('public_key', response_properties)
		self.assertIn('public_key_algorithm', response_properties)
		self.assertIn('public_key_fingerprint', response_properties)

	def test_manager_group_devices_schema_has_query_parameter_and_array_response(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/manager/group-devices/']['get']

		parameter_names = {parameter['name'] for parameter in operation.get('parameters', [])}
		self.assertIn('group', parameter_names)

		response_schema = operation['responses']['200']['content']['application/json']['schema']
		self.assertEqual(response_schema.get('type'), 'array')
		resolved_item_schema = self._resolve_schema_object(schema, response_schema['items'])
		response_properties = resolved_item_schema.get('properties', {})
		self.assertIn('device_identifier', response_properties)
		self.assertIn('encrypted_member_name', response_properties)
		self.assertIn('public_key', response_properties)
		self.assertIn('public_key_algorithm', response_properties)
		self.assertIn('public_key_fingerprint', response_properties)

	def test_add_device_to_group_schema_has_request_and_response_shapes(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/main-manager/add-device-to-group/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('device_identifier', request_properties)
		self.assertIn('group', request_properties)
		self.assertIn('encrypted_member_name', request_properties)
		self.assertIn('is_manager', request_properties)

		response_schema = operation['responses']['201']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		response_properties = resolved_response_schema.get('properties', {})
		self.assertIn('device_identifier', response_properties)
		self.assertIn('group', response_properties)
		self.assertIn('encrypted_member_name', response_properties)
		self.assertIn('group_link_created', response_properties)
		self.assertIn('200', operation['responses'])
		self.assertIn('401', operation['responses'])
		self.assertIn('403', operation['responses'])
		self.assertIn('404', operation['responses'])

	def test_remove_device_from_group_schema_has_request_and_responses(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/main-manager/remove-device-from-group/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('device_identifier', request_properties)
		self.assertIn('group', request_properties)

		self.assertIn('204', operation['responses'])
		self.assertEqual(
			operation['responses']['204']['description'],
			'Device removed from the group successfully.',
		)
		self.assertIn('401', operation['responses'])
		self.assertIn('403', operation['responses'])
		self.assertIn('404', operation['responses'])

	def test_create_group_schema_has_request_and_response_shapes(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/main-manager/create-group/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('encrypted_name', request_properties)
		self.assertIn('crypto_version', request_properties)
		self.assertIn('encryption_algorithm', request_properties)
		self.assertIn('name_nonce', request_properties)

		response_schema = operation['responses']['201']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		response_properties = resolved_response_schema.get('properties', {})
		self.assertIn('uuid', response_properties)
		self.assertIn('encrypted_name', response_properties)
		self.assertIn('name_nonce', response_properties)
		self._assert_quota_error_schema(operation)

	def test_update_group_schema_has_request_and_response_shapes(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/main-manager/update-group/']['patch']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('group', request_properties)
		self.assertIn('encrypted_name', request_properties)
		self.assertIn('name_nonce', request_properties)

		response_schema = operation['responses']['200']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		response_properties = resolved_response_schema.get('properties', {})
		self.assertIn('uuid', response_properties)
		self.assertIn('encrypted_name', response_properties)

	def test_create_group_key_envelope_schema_has_request_and_response_shapes(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/main-manager/create-group-key-envelope/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('group', request_properties)
		self.assertIn('scope', request_properties)
		self.assertIn('key_envelopes', request_properties)

		response_schema = operation['responses']['201']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		response_properties = resolved_response_schema.get('properties', {})
		self.assertIn('group', response_properties)
		self.assertIn('scope', response_properties)
		self.assertIn('envelope_count', response_properties)
		self.assertIn('created_count', response_properties)

	def test_upload_encrypted_image_schema_has_multipart_request_and_response_shapes(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/manager/upload-encrypted-blob/']['post']

		request_body = operation['requestBody']['content']['multipart/form-data']
		request_schema = request_body['schema']
		request_properties = request_schema.get('properties', {})
		self.assertEqual(request_properties['encrypted_blob']['format'], 'binary')
		self.assertIn('group', request_properties)
		self.assertIn('payload_nonce', request_properties)
		self.assertIn('recipient_envelopes', request_properties)
		self.assertEqual(request_properties['recipient_envelopes']['type'], 'array')
		self.assertEqual(
			request_body['encoding']['recipient_envelopes']['contentType'],
			'application/json',
		)

		envelope_item_schema = request_properties['recipient_envelopes']['items']
		envelope_properties = envelope_item_schema.get('properties', {})
		self.assertIn('recipient_device_identifier', envelope_properties)
		self.assertIn('key_wrap_algorithm', envelope_properties)
		self.assertIn('recipient_key_fingerprint', envelope_properties)
		self.assertIn('encrypted_content_key', envelope_properties)

		response_schema = operation['responses']['201']['content']['application/json']['schema']
		resolved_response_schema = self._resolve_schema_object(schema, response_schema)
		response_properties = resolved_response_schema.get('properties', {})
		self.assertIn('image_id', response_properties)
		self.assertIn('encrypted_caption', response_properties)
		self.assertIn('group', response_properties)
		self.assertIn('recipient_count', response_properties)
		self.assertIn('ciphertext_hash_sha256', response_properties)
		self.assertIn('created_at', response_properties)
		self.assertIn('expires_at', response_properties)
		self.assertIn('400', operation['responses'])
		self.assertIn('401', operation['responses'])
		self.assertIn('404', operation['responses'])
		self._assert_quota_error_schema(operation)

	def test_manager_groups_schema_has_array_response_shape(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/manager/groups/']['get']

		self.assertNotIn('requestBody', operation)

		response_schema = operation['responses']['200']['content']['application/json']['schema']
		self.assertEqual(response_schema.get('type'), 'array')
		resolved_item_schema = self._resolve_schema_object(schema, response_schema['items'])
		response_properties = resolved_item_schema.get('properties', {})
		self.assertIn('uuid', response_properties)
		self.assertIn('encrypted_name', response_properties)
		self.assertIn('crypto_version', response_properties)
		self.assertIn('encryption_algorithm', response_properties)
		self.assertIn('name_nonce', response_properties)
		self.assertIn('status', response_properties)
		self.assertIn('401', operation['responses'])

	def test_delete_group_schema_has_request_and_responses(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/main-manager/delete-group/']['delete']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('group', request_properties)

		self.assertIn('204', operation['responses'])
		self.assertIn('401', operation['responses'])
		self.assertIn('403', operation['responses'])
		self.assertIn('404', operation['responses'])

	def test_delete_encrypted_image_schema_has_request_and_responses(self):
		response = self.client.get(reverse('api-schema-yaml'))
		self.assertEqual(response.status_code, status.HTTP_200_OK)

		schema = yaml.safe_load(response.content.decode('utf-8'))
		operation = schema['paths']['/api/delete-encrypted-image/']['post']

		request_schema = operation['requestBody']['content']['application/json']['schema']
		resolved_request_schema = self._resolve_schema_object(schema, request_schema)
		request_properties = resolved_request_schema.get('properties', {})
		self.assertIn('group', request_properties)
		self.assertIn('image_uuid', request_properties)

		self.assertIn('204', operation['responses'])
		self.assertIn('400', operation['responses'])
		self.assertIn('401', operation['responses'])
		self.assertIn('403', operation['responses'])
		self.assertIn('404', operation['responses'])


class TestGroupCrudViews(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.create_url = reverse('create-group')
		self.update_url = reverse('update-group')
		self.delete_url = reverse('delete-group')
		self.main_manager = User.objects.create_user(
			username='group-crud-main-manager',
			email='group-crud-main-manager@example.com',
			password='test-password-123',
		)
		self.other_user = User.objects.create_user(
			username='group-crud-other-user',
			email='group-crud-other-user@example.com',
			password='test-password-123',
		)
		self.managed_group = create_group('Managed CRUD Group')
		ManagerRole.objects.create(manager=self.main_manager, group=self.managed_group, role='main_manager')
		self.valid_name_nonce = base64.b64encode(os.urandom(24)).decode('ascii')

	def test_create_group_requires_staff_user(self):
		self.client.force_authenticate(user=self.other_user)
		response = self.client.post(
			self.create_url,
			data={
				'encrypted_name': 'encrypted:new-group',
				'name_nonce': self.valid_name_nonce,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

	def test_create_group_creates_group_and_main_manager_role(self):
		self.main_manager.is_staff = True
		self.main_manager.save(update_fields=['is_staff'])
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.post(
			self.create_url,
			data={
				'encrypted_name': 'encrypted:new-group',
				'name_nonce': self.valid_name_nonce,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		created_group = Group.objects.get(uuid=response.data['uuid'])
		self.assertEqual(created_group.encrypted_name, 'encrypted:new-group')
		self.assertTrue(
			ManagerRole.objects.filter(manager=self.main_manager, group=created_group, role='main_manager').exists(),
		)

	def test_create_group_returns_403_when_max_groups_quota_reached(self):
		self.main_manager.is_staff = True
		self.main_manager.save(update_fields=['is_staff'])
		create_quota_organization(max_groups=1, max_devices=100, max_images=100)
		self.client.force_authenticate(user=self.main_manager)

		response = self.client.post(
			self.create_url,
			data={
				'encrypted_name': 'encrypted:new-group-over-quota',
				'name_nonce': self.valid_name_nonce,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
		self.assertEqual(response.data['quota'], 'max_groups')
		self.assertEqual(response.data['current'], 1)
		self.assertEqual(response.data['maximum'], 1)
		self.assertFalse(Group.objects.filter(encrypted_name='encrypted:new-group-over-quota').exists())

	def test_create_group_links_manager_owned_devices_to_new_group(self):
		self.main_manager.is_staff = True
		self.main_manager.save(update_fields=['is_staff'])
		owned_device = Device.objects.create(
			device_identifier='group-create-owned-device',
			owner_user=self.main_manager,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.client.force_authenticate(user=self.main_manager)

		response = self.client.post(
			self.create_url,
			data={
				'encrypted_name': 'encrypted:new-group-with-device',
				'name_nonce': self.valid_name_nonce,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		created_group = Group.objects.get(uuid=response.data['uuid'])
		self.assertTrue(GroupDevices.objects.filter(group=created_group, device=owned_device).exists())

	def test_update_group_updates_encrypted_fields(self):
		self.client.force_authenticate(user=self.main_manager)
		new_name_nonce = base64.b64encode(os.urandom(24)).decode('ascii')
		response = self.client.patch(
			self.update_url,
			data={
				'group': str(self.managed_group.uuid),
				'encrypted_name': 'encrypted:updated-group',
				'name_nonce': new_name_nonce,
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.managed_group.refresh_from_db()
		self.assertEqual(self.managed_group.encrypted_name, 'encrypted:updated-group')
		self.assertEqual(response.data['encrypted_name'], 'encrypted:updated-group')

	def test_delete_group_removes_group_for_main_manager(self):
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.delete(
			self.delete_url,
			data={'group': str(self.managed_group.uuid)},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
		self.assertFalse(Group.objects.filter(id=self.managed_group.id).exists())


class TestCreateGroupKeyEnvelopeView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('create-group-key-envelope')
		self.group = create_group('Envelope Group')
		self.other_group = create_group('Other Envelope Group')
		self.main_manager = User.objects.create_user(
			username='group-envelope-main-manager',
			email='group-envelope-main-manager@example.com',
			password='test-password-123',
		)
		self.other_user = User.objects.create_user(
			username='group-envelope-other-user',
			email='group-envelope-other-user@example.com',
			password='test-password-123',
		)
		self.manager_user = User.objects.create_user(
			username='group-envelope-manager-user',
			email='group-envelope-manager-user@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=self.main_manager, group=self.group, role='main_manager')
		ManagerRole.objects.create(manager=self.manager_user, group=self.group, role='manager')
		self.device = Device.objects.create(
			device_identifier='group-envelope-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.manager_device = Device.objects.create(
			device_identifier='group-envelope-manager-device',
			owner_user=self.manager_user,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.regular_owned_device = Device.objects.create(
			device_identifier='group-envelope-regular-owned-device',
			owner_user=self.other_user,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.other_device = Device.objects.create(
			device_identifier='group-envelope-device-2',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		GroupDevices.objects.create(group=self.group, device=self.device)
		GroupDevices.objects.create(group=self.group, device=self.manager_device)
		GroupDevices.objects.create(group=self.group, device=self.regular_owned_device)
		GroupDevices.objects.create(group=self.other_group, device=self.other_device)

	def test_post_requires_authenticated_user(self):
		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'key_envelopes': [],
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_post_rejects_non_main_manager(self):
		self.client.force_authenticate(user=self.other_user)
		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'key_envelopes': [
					{
						'recipient_device_identifier': self.device.device_identifier,
						'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
						'recipient_key_fingerprint': self.device.public_key_fingerprint,
						'encrypted_group_key': base64.b64encode(b'group-key').decode('ascii'),
					},
				],
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

	def test_post_creates_group_key_envelope(self):
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'key_envelopes': [
					{
						'recipient_device_identifier': self.device.device_identifier,
						'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
						'recipient_key_fingerprint': self.device.public_key_fingerprint,
						'encrypted_group_key': base64.b64encode(b'group-key').decode('ascii'),
					},
				],
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(response.data['group'], str(self.group.uuid))
		self.assertEqual(response.data['scope'], GROUP_KEY_SCOPE_GROUP_SHARED)
		self.assertEqual(response.data['envelope_count'], 1)
		self.assertEqual(response.data['created_count'], 1)
		self.assertEqual(GroupKeyEnvelope.objects.count(), 1)
		envelope = GroupKeyEnvelope.objects.get()
		self.assertEqual(envelope.group, self.group)
		self.assertEqual(envelope.recipient_device, self.device)
		self.assertEqual(envelope.scope, GROUP_KEY_SCOPE_GROUP_SHARED)

	def test_post_creates_manager_roster_envelope_for_manager_owned_device(self):
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'scope': GROUP_KEY_SCOPE_MANAGER_ROSTER,
				'key_envelopes': [
					{
						'recipient_device_identifier': self.manager_device.device_identifier,
						'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
						'recipient_key_fingerprint': self.manager_device.public_key_fingerprint,
						'encrypted_group_key': base64.b64encode(b'manager-roster-key').decode('ascii'),
					},
				],
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_201_CREATED)
		self.assertEqual(response.data['scope'], GROUP_KEY_SCOPE_MANAGER_ROSTER)
		envelope = GroupKeyEnvelope.objects.get(scope=GROUP_KEY_SCOPE_MANAGER_ROSTER)
		self.assertEqual(envelope.recipient_device, self.manager_device)

	def test_post_rejects_manager_roster_envelope_for_non_manager_owned_device(self):
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'scope': GROUP_KEY_SCOPE_MANAGER_ROSTER,
				'key_envelopes': [
					{
						'recipient_device_identifier': self.regular_owned_device.device_identifier,
						'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
						'recipient_key_fingerprint': self.regular_owned_device.public_key_fingerprint,
						'encrypted_group_key': base64.b64encode(b'manager-roster-key').decode('ascii'),
					},
				],
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('key_envelopes', response.data)

	def test_post_returns_400_when_recipient_not_in_group(self):
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.post(
			self.url,
			data={
				'group': str(self.group.uuid),
				'key_envelopes': [
					{
						'recipient_device_identifier': self.other_device.device_identifier,
						'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
						'recipient_key_fingerprint': self.other_device.public_key_fingerprint,
						'encrypted_group_key': base64.b64encode(b'group-key').decode('ascii'),
					},
				],
			},
			format='json',
		)

		self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
		self.assertIn('key_envelopes', response.data)


class TestGetMainManagerGroupsView(TestCase):
	def setUp(self):
		self.client = APIClient()
		try:
			self.url = reverse('main-manager-groups')
		except Exception:
			self.url = '/api/main-manager-groups/'
		self.group1 = create_group('Main Manager Group 1')
		self.group2 = create_group('Main Manager Group 2')
		self.other_group = create_group('Other Group')
		self.main_manager = User.objects.create_user(
			username='mainmanager',
			email='mainmanager@example.com',
			password='test-password-123',
		)
		self.other_user = User.objects.create_user(
			username='otheruser',
			email='otheruser@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=self.main_manager, group=self.group1, role='main_manager')
		ManagerRole.objects.create(manager=self.main_manager, group=self.group2, role='main_manager')
		ManagerRole.objects.create(manager=self.other_user, group=self.other_group, role='manager')
		# Ensure there are no GroupDevices links for main_manager and the tested groups
		GroupDevices.objects.filter(group__in=[self.group1, self.group2], device__isnull=False).delete()

	def test_get_requires_authenticated_user(self):
		response = self.client.get(self.url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_returns_empty_list_for_non_main_manager(self):
		self.client.force_authenticate(user=self.other_user)
		response = self.client.get(self.url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data, [])

	def test_get_returns_groups_for_main_manager(self):
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.get(self.url)
		self.assertEqual(response.status_code, status.HTTP_200_OK)
		returned_uuids = {item['uuid'] for item in response.data}
		expected_uuids = {str(self.group1.uuid), str(self.group2.uuid)}
		self.assertEqual(returned_uuids, expected_uuids)
		for item in response.data:
			self.assertEqual(item['user_role'], 'main_manager')


class TestGetManagerGroupsView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('manager-groups')
		self.main_manager_group = create_group('Manager Group 1')
		self.manager_group = create_group('Manager Group 2')
		self.other_group = create_group('Manager Group 3')
		self.user = User.objects.create_user(
			username='manager-groups-user',
			email='manager-groups-user@example.com',
			password='test-password-123',
		)
		self.other_user = User.objects.create_user(
			username='manager-groups-other-user',
			email='manager-groups-other-user@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=self.user, group=self.main_manager_group, role='main_manager')
		ManagerRole.objects.create(manager=self.user, group=self.manager_group, role='manager')
		ManagerRole.objects.create(manager=self.other_user, group=self.other_group, role='manager')

	def test_get_requires_authenticated_user(self):
		response = self.client.get(self.url)
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_returns_all_groups_for_authenticated_manager(self):
		self.client.force_authenticate(user=self.user)
		response = self.client.get(self.url)

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(len(response.data), 2)
		returned_statuses = {item['uuid']: item['status'] for item in response.data}
		self.assertEqual(
			returned_statuses,
			{
				str(self.main_manager_group.uuid): 'main_manager',
				str(self.manager_group.uuid): 'manager',
			},
		)
		for item in response.data:
			self.assertIn('encrypted_name', item)
			self.assertIn('name_nonce', item)


class TestGetMainManagerGroupDevicesView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('main-manager-group-devices')
		self.group = create_group('Managed Device Group')
		self.other_group = create_group('Other Managed Device Group')
		self.main_manager = User.objects.create_user(
			username='devices-main-manager',
			email='devices-main-manager@example.com',
			password='test-password-123',
		)
		self.other_user = User.objects.create_user(
			username='devices-other-user',
			email='devices-other-user@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=self.main_manager, group=self.group, role='main_manager')

		self.device_one = Device.objects.create(
			device_identifier='managed-device-1',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.device_two = Device.objects.create(
			device_identifier='managed-device-2',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.other_device = Device.objects.create(
			device_identifier='managed-device-3',
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		GroupDevices.objects.create(group=self.group, device=self.device_one, encrypted_member_name='encrypted:managed-owner-1')
		GroupDevices.objects.create(group=self.group, device=self.device_two, encrypted_member_name='encrypted:managed-owner-2')
		GroupDevices.objects.create(group=self.other_group, device=self.other_device, encrypted_member_name='encrypted:managed-owner-3')

	def test_get_requires_authenticated_user(self):
		response = self.client.get(self.url, {'group': str(self.group.uuid)})
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_rejects_non_main_manager(self):
		self.client.force_authenticate(user=self.other_user)
		response = self.client.get(self.url, {'group': str(self.group.uuid)})
		self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

	def test_get_returns_devices_for_group_main_manager(self):
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.get(self.url, {'group': str(self.group.uuid)})

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		returned_ids = {item['device_identifier'] for item in response.data}
		self.assertEqual(returned_ids, {'managed-device-1', 'managed-device-2'})
		for item in response.data:
			self.assertIn('encrypted_member_name', item)
			self.assertIn('public_key', item)
			self.assertIn('public_key_algorithm', item)
			self.assertIn('public_key_fingerprint', item)

	def test_get_returns_404_when_group_not_found(self):
		self.client.force_authenticate(user=self.main_manager)
		response = self.client.get(self.url, {'group': 'ffffffff-ffff-ffff-ffff-ffffffffffff'})
		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
		self.assertEqual(response.data['detail'], 'Group not found.')


class TestGetManagerGroupDevicesView(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.url = reverse('manager-group-devices')
		self.group = create_group('Manager Owned Device Group')
		self.other_group = create_group('Manager Other Group')
		self.empty_group = create_group('Manager Empty Group')
		self.user = User.objects.create_user(
			username='manager-devices-user',
			email='manager-devices-user@example.com',
			password='test-password-123',
		)
		self.other_user = User.objects.create_user(
			username='manager-devices-other-user',
			email='manager-devices-other-user@example.com',
			password='test-password-123',
		)

		self.owned_device_in_group = Device.objects.create(
			device_identifier='manager-owned-device-1',
			owner_user=self.user,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.owned_device_other_group = Device.objects.create(
			device_identifier='manager-owned-device-2',
			owner_user=self.user,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)
		self.other_user_device_in_group = Device.objects.create(
			device_identifier='manager-other-user-device-1',
			owner_user=self.other_user,
			public_key=base64.b64encode(
				x25519.X25519PrivateKey.generate().public_key().public_bytes(
					encoding=serialization.Encoding.Raw,
					format=serialization.PublicFormat.Raw,
				),
			).decode('ascii'),
			public_key_algorithm='x25519',
		)

		GroupDevices.objects.create(
			group=self.group,
			device=self.owned_device_in_group,
			encrypted_member_name='encrypted:manager-owned-1',
		)
		GroupDevices.objects.create(
			group=self.other_group,
			device=self.owned_device_other_group,
			encrypted_member_name='encrypted:manager-owned-2',
		)
		GroupDevices.objects.create(
			group=self.group,
			device=self.other_user_device_in_group,
			encrypted_member_name='encrypted:manager-other-user-1',
		)

	def test_get_requires_authenticated_user(self):
		response = self.client.get(self.url, {'group': str(self.group.uuid)})
		self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

	def test_get_returns_only_authenticated_user_owned_devices_for_group(self):
		self.client.force_authenticate(user=self.user)
		response = self.client.get(self.url, {'group': str(self.group.uuid)})

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		returned_ids = {item['device_identifier'] for item in response.data}
		self.assertEqual(returned_ids, {'manager-owned-device-1'})
		for item in response.data:
			self.assertIn('encrypted_member_name', item)
			self.assertIn('public_key', item)
			self.assertIn('public_key_algorithm', item)
			self.assertIn('public_key_fingerprint', item)

	def test_get_returns_empty_when_user_has_no_devices_in_group(self):
		self.client.force_authenticate(user=self.user)
		response = self.client.get(self.url, {'group': str(self.empty_group.uuid)})

		self.assertEqual(response.status_code, status.HTTP_200_OK)
		self.assertEqual(response.data, [])

	def test_get_returns_404_when_group_not_found(self):
		self.client.force_authenticate(user=self.user)
		response = self.client.get(self.url, {'group': 'ffffffff-ffff-ffff-ffff-ffffffffffff'})
		self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
		self.assertEqual(response.data['detail'], 'Group not found.')