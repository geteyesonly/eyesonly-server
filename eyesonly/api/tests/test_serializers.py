import base64
import os
from datetime import timedelta

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.test import SimpleTestCase
from django.utils import timezone

from django.contrib.auth import get_user_model

from eyesonly.authentication.device_challenge_crypto import DEFAULT_KEY_WRAP_ALGORITHM
from eyesonly.api.serializers import (
	CreateGroupKeyEnvelopeSerializer,
    CreateGroupSerializer,
	GetDeviceGroupKeyEnvelopesSerializer,
    DeleteGroupSerializer,
	DeviceAuthChallengeRequestSerializer,
	DeviceAuthTokenRequestSerializer,
	GroupDeviceSerializer,
	MainManagerGroupSerializer,
	UpdateGroupSerializer,
	UserGroupSerializer,
	RecipientEnvelopeSerializer,
	UploadEncryptedImageSerializer,
)
from eyesonly.models import (
	Device,
	Group,
	GroupDevices,
	GROUP_KEY_SCOPE_GROUP_SHARED,
	GROUP_KEY_SCOPE_MANAGER_ROSTER,
	ManagerRole,
)

User = get_user_model()


def create_group(encrypted_name='encrypted_group_name'):
	return Group.objects.create(
		encrypted_name=encrypted_name,
		name_nonce=os.urandom(24),
	)


class TestDeviceAuthChallengeRequestSerializer(SimpleTestCase):
	def test_serializer_is_valid_with_device_identifier(self):
		serializer = DeviceAuthChallengeRequestSerializer(
			data={'device_identifier': 'device-identifier-123'},
		)

		self.assertTrue(serializer.is_valid())
		self.assertEqual(serializer.validated_data['device_identifier'], 'device-identifier-123')

	def test_serializer_requires_device_identifier(self):
		serializer = DeviceAuthChallengeRequestSerializer(data={})

		self.assertFalse(serializer.is_valid())
		self.assertIn('device_identifier', serializer.errors)

	def test_serializer_rejects_device_identifier_longer_than_255_chars(self):
		serializer = DeviceAuthChallengeRequestSerializer(
			data={'device_identifier': 'a' * 256},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('device_identifier', serializer.errors)


class TestDeviceAuthTokenRequestSerializer(SimpleTestCase):
	def test_serializer_is_valid_with_device_identifier_and_challenge(self):
		serializer = DeviceAuthTokenRequestSerializer(
			data={
				'device_identifier': 'device-identifier-123',
				'challenge': 'challenge-token-123',
			},
		)

		self.assertTrue(serializer.is_valid())
		self.assertEqual(serializer.validated_data['device_identifier'], 'device-identifier-123')
		self.assertEqual(serializer.validated_data['challenge'], 'challenge-token-123')

	def test_serializer_requires_device_identifier(self):
		serializer = DeviceAuthTokenRequestSerializer(
			data={'challenge': 'challenge-token-123'},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('device_identifier', serializer.errors)

	def test_serializer_requires_challenge(self):
		serializer = DeviceAuthTokenRequestSerializer(
			data={'device_identifier': 'device-identifier-123'},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('challenge', serializer.errors)

	def test_serializer_rejects_device_identifier_longer_than_255_chars(self):
		serializer = DeviceAuthTokenRequestSerializer(
			data={
				'device_identifier': 'a' * 256,
				'challenge': 'challenge-token-123',
			},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('device_identifier', serializer.errors)

	def test_serializer_rejects_challenge_longer_than_255_chars(self):
		serializer = DeviceAuthTokenRequestSerializer(
			data={
				'device_identifier': 'device-identifier-123',
				'challenge': 'a' * 256,
			},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('challenge', serializer.errors)


class TestRecipientEnvelopeSerializer(SimpleTestCase):
	def _valid_payload(self):
		return {
			'recipient_device_identifier': 'device-one',
			'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
			'recipient_key_fingerprint': 'a' * 64,
			'encrypted_content_key': base64.b64encode(b'encrypted-key').decode('ascii'),
		}

	def test_serializer_is_valid_with_expected_payload(self):
		serializer = RecipientEnvelopeSerializer(data=self._valid_payload())

		self.assertTrue(serializer.is_valid(), serializer.errors)

	def test_serializer_rejects_unsupported_key_wrap_algorithm(self):
		payload = self._valid_payload()
		payload['key_wrap_algorithm'] = 'rsa-oaep'
		serializer = RecipientEnvelopeSerializer(data=payload)

		self.assertFalse(serializer.is_valid())
		self.assertIn('key_wrap_algorithm', serializer.errors)

	def test_serializer_rejects_invalid_recipient_key_fingerprint_format(self):
		payload = self._valid_payload()
		payload['recipient_key_fingerprint'] = 'XYZ-not-hex'
		serializer = RecipientEnvelopeSerializer(data=payload)

		self.assertFalse(serializer.is_valid())
		self.assertIn('recipient_key_fingerprint', serializer.errors)

	def test_serializer_rejects_invalid_encrypted_content_key_base64(self):
		payload = self._valid_payload()
		payload['encrypted_content_key'] = 'not-base64@@@'
		serializer = RecipientEnvelopeSerializer(data=payload)

		self.assertFalse(serializer.is_valid())
		self.assertIn('encrypted_content_key', serializer.errors)


class TestEncryptedBlobSerializer(TestCase):
	def _valid_payload(self):
		group = create_group('Upload Serializer Group')
		return {
			'encrypted_blob': SimpleUploadedFile(
				'cipher.bin',
				b'ciphertext-bytes',
				content_type='application/octet-stream',
			),
			'group': str(group.uuid),
			'crypto_version': 1,
			'encryption_algorithm': 'xchacha20poly1305',
			'payload_nonce': base64.b64encode(b'0' * 24).decode('ascii'),
			'recipient_envelopes': [
				{
					'recipient_device_identifier': 'device-one',
					'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
					'recipient_key_fingerprint': 'a' * 64,
					'encrypted_content_key': base64.b64encode(b'encrypted-key').decode('ascii'),
				},
			],
			'expires_at': timezone.now() + timedelta(hours=1),
			'client_ciphertext_hash_sha256': 'b' * 64,
		}

	def test_serializer_is_valid_with_expected_upload_payload(self):
		serializer = UploadEncryptedImageSerializer(data=self._valid_payload())

		self.assertTrue(serializer.is_valid(), serializer.errors)
		self.assertIn('group_obj', serializer.validated_data)

	def test_serializer_rejects_unknown_group(self):
		payload = self._valid_payload()
		Group.objects.filter(uuid=payload['group']).delete()
		serializer = UploadEncryptedImageSerializer(data=payload)

		self.assertFalse(serializer.is_valid())
		self.assertIn('group', serializer.errors)

	def test_serializer_rejects_payload_nonce_with_wrong_length(self):
		payload = self._valid_payload()
		payload['payload_nonce'] = base64.b64encode(b'1' * 12).decode('ascii')
		serializer = UploadEncryptedImageSerializer(data=payload)

		self.assertFalse(serializer.is_valid())
		self.assertIn('payload_nonce', serializer.errors)

	def test_serializer_rejects_duplicate_recipient_device_identifiers(self):
		payload = self._valid_payload()
		payload['recipient_envelopes'].append(
			{
				'recipient_device_identifier': 'device-one',
				'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
				'recipient_key_fingerprint': 'c' * 64,
				'encrypted_content_key': base64.b64encode(b'another-key').decode('ascii'),
			},
		)
		serializer = UploadEncryptedImageSerializer(data=payload)

		self.assertFalse(serializer.is_valid())
		self.assertIn('recipient_envelopes', serializer.errors)


class TestUserGroupSerializer(TestCase):
	def test_serializer_always_returns_member_for_device(self):
		# Devices cannot be linked to users, so role resolution is not possible
		group = create_group('encrypted_group_serializer_group')
		serializer = UserGroupSerializer(group, context={})
		self.assertEqual(serializer.data['encrypted_name'], group.encrypted_name)
		self.assertIn('name_nonce', serializer.data)
		self.assertEqual(serializer.data['user_role'], 'member')


class TestMainManagerGroupSerializer(TestCase):
	def setUp(self):
		self.group = create_group('encrypted_serializer_test_group')
		self.main_manager = User.objects.create_user(
			username='mm-serializer',
			email='mm-serializer@example.com',
			password='test-password-123',
		)
		self.manager = User.objects.create_user(
			username='m-serializer',
			email='m-serializer@example.com',
			password='test-password-123',
		)
		self.other_user = User.objects.create_user(
			username='other-serializer',
			email='other-serializer@example.com',
			password='test-password-123',
		)
		ManagerRole.objects.create(manager=self.main_manager, group=self.group, role='main_manager')
		ManagerRole.objects.create(manager=self.manager, group=self.group, role='manager')

	def _make_request(self, user):
		from unittest.mock import Mock
		request = Mock()
		request.user = user
		return request

	def test_returns_main_manager_role(self):
		serializer = MainManagerGroupSerializer(self.group, context={'request': self._make_request(self.main_manager)})
		self.assertEqual(serializer.data['encrypted_name'], self.group.encrypted_name)
		self.assertEqual(serializer.data['user_role'], 'main_manager')

	def test_returns_manager_role(self):
		serializer = MainManagerGroupSerializer(self.group, context={'request': self._make_request(self.manager)})
		self.assertEqual(serializer.data['user_role'], 'manager')

	def test_returns_member_for_non_manager(self):
		serializer = MainManagerGroupSerializer(self.group, context={'request': self._make_request(self.other_user)})
		self.assertEqual(serializer.data['user_role'], 'member')

	def test_returns_member_without_request(self):
		serializer = MainManagerGroupSerializer(self.group, context={})
		self.assertEqual(serializer.data['user_role'], 'member')


class TestGroupMutationSerializers(TestCase):
	def setUp(self):
		self.group = create_group('encrypted_serializer_mutation_group')

	def test_create_group_serializer_decodes_nonce(self):
		name_nonce = base64.b64encode(os.urandom(24)).decode('ascii')
		serializer = CreateGroupSerializer(
			data={
				'encrypted_name': 'encrypted:new-group',
				'name_nonce': name_nonce,
			},
		)

		self.assertTrue(serializer.is_valid(), serializer.errors)
		self.assertEqual(serializer.validated_data['encrypted_name'], 'encrypted:new-group')
		self.assertEqual(serializer.validated_data['crypto_version'], 1)
		self.assertEqual(serializer.validated_data['encryption_algorithm'], 'xchacha20poly1305')
		self.assertEqual(base64.b64encode(serializer.validated_data['name_nonce_bytes']).decode('ascii'), name_nonce)

	def test_update_group_serializer_requires_mutation_field(self):
		serializer = UpdateGroupSerializer(
			data={
				'group': str(self.group.uuid),
			},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('non_field_errors', serializer.errors)

	def test_delete_group_serializer_requires_group(self):
		serializer = DeleteGroupSerializer(data={})

		self.assertFalse(serializer.is_valid())
		self.assertIn('group', serializer.errors)

	def test_create_group_key_envelope_serializer_rejects_duplicate_recipients(self):
		serializer = CreateGroupKeyEnvelopeSerializer(
			data={
				'group': str(self.group.uuid),
				'key_envelopes': [
					{
						'recipient_device_identifier': 'device-1',
						'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
						'recipient_key_fingerprint': 'a' * 64,
						'encrypted_group_key': base64.b64encode(b'group-key-1').decode('ascii'),
					},
					{
						'recipient_device_identifier': 'device-1',
						'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
						'recipient_key_fingerprint': 'b' * 64,
						'encrypted_group_key': base64.b64encode(b'group-key-2').decode('ascii'),
					},
				],
			},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('key_envelopes', serializer.errors)

	def test_get_device_group_key_envelopes_serializer_rejects_duplicate_groups(self):
		serializer = GetDeviceGroupKeyEnvelopesSerializer(
			data={
				'groups': [str(self.group.uuid), str(self.group.uuid)],
			},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('groups', serializer.errors)

	def test_get_device_group_key_envelopes_serializer_rejects_duplicate_scopes(self):
		serializer = GetDeviceGroupKeyEnvelopesSerializer(
			data={
				'groups': [str(self.group.uuid)],
				'scopes': [GROUP_KEY_SCOPE_GROUP_SHARED, GROUP_KEY_SCOPE_GROUP_SHARED],
			},
		)

		self.assertFalse(serializer.is_valid())
		self.assertIn('scopes', serializer.errors)

	def test_create_group_key_envelope_serializer_accepts_explicit_scope(self):
		serializer = CreateGroupKeyEnvelopeSerializer(
			data={
				'group': str(self.group.uuid),
				'scope': GROUP_KEY_SCOPE_MANAGER_ROSTER,
				'key_envelopes': [
					{
						'recipient_device_identifier': 'device-1',
						'key_wrap_algorithm': DEFAULT_KEY_WRAP_ALGORITHM,
						'recipient_key_fingerprint': 'a' * 64,
						'encrypted_group_key': base64.b64encode(b'group-key-1').decode('ascii'),
					},
				],
			},
		)

		self.assertTrue(serializer.is_valid(), serializer.errors)
		self.assertEqual(serializer.validated_data['scope'], GROUP_KEY_SCOPE_MANAGER_ROSTER)


class TestGroupDeviceSerializer(TestCase):
	def test_serializes_expected_device_fields(self):
		device = Device.objects.create(
			device_identifier='serializer-device-1',
			public_key='serializer-public-key',
			public_key_algorithm='x25519',
		)
		group = Group.objects.create(encrypted_name='serializer-group', name_nonce=b'0' * 24)
		group_device = GroupDevices.objects.create(
			group=group,
			device=device,
			encrypted_member_name='encrypted:serializer-member',
		)

		serializer = GroupDeviceSerializer(group_device)

		self.assertEqual(serializer.data['device_identifier'], device.device_identifier)
		self.assertEqual(serializer.data['encrypted_member_name'], 'encrypted:serializer-member')
		self.assertEqual(serializer.data['public_key'], device.public_key)
		self.assertEqual(serializer.data['public_key_algorithm'], device.public_key_algorithm)
		self.assertEqual(serializer.data['public_key_fingerprint'], device.public_key_fingerprint)
		self.assertNotIn('created_at', serializer.data)
