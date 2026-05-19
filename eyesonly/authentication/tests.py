import hashlib, os
from datetime import timedelta

from django.contrib.auth.models import AnonymousUser
from django.test import TestCase
from django.utils import timezone
from rest_framework import exceptions
from rest_framework.test import APIRequestFactory

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt
from eyesonly.authentication import device_challenge_crypto


from eyesonly.authentication.device_authentication import (
	DeviceAuthentication,
	DeviceTokenAuthentication,
)
from eyesonly.models import Device, DeviceAuthToken


def test_encrypt_decrypt_device_challenge_python_only():
	# Generate device key pair
	device_private = x25519.X25519PrivateKey.generate()
	device_public = device_private.public_key()

	# Ephemeral key pair (simulates server)
	ephemeral_private = x25519.X25519PrivateKey.generate()
	ephemeral_public = ephemeral_private.public_key()

	# Shared secret (server side)
	shared_secret_srv = ephemeral_private.exchange(device_public)
	# Shared secret (client side)
	shared_secret_cli = device_private.exchange(ephemeral_public)
	assert shared_secret_srv == shared_secret_cli

	# Derive symmetric key (HKDF)
	info = device_challenge_crypto.DEVICE_CHALLENGE_HKDF_INFO
	derived_key_srv = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=None,
		info=info,
	).derive(shared_secret_srv)
	derived_key_cli = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=None,
		info=info,
	).derive(shared_secret_cli)
	assert derived_key_srv == derived_key_cli

	# Encrypt (server)
	nonce = b'1' * 24
	plaintext = b'hello python xchacha20poly1305!'
	ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
		plaintext,
		aad=None,
		nonce=nonce,
		key=derived_key_srv,
	)

	# Decrypt (client)
	decrypted = crypto_aead_xchacha20poly1305_ietf_decrypt(
		ciphertext,
		aad=None,
		nonce=nonce,
		key=derived_key_cli,
	)
	assert decrypted == plaintext

def test_encrypt_decrypt_with_random_nonce():
	device_private = x25519.X25519PrivateKey.generate()
	device_public = device_private.public_key()
	ephemeral_private = x25519.X25519PrivateKey.generate()
	ephemeral_public = ephemeral_private.public_key()
	shared_secret = ephemeral_private.exchange(device_public)
	info = device_challenge_crypto.DEVICE_CHALLENGE_HKDF_INFO
	derived_key = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=None,
		info=info,
	).derive(shared_secret)

	nonce = os.urandom(24)
	plaintext = b'python random nonce test'
	ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
		plaintext,
		aad=None,
		nonce=nonce,
		key=derived_key,
	)
	# Decrypt with same key/nonce
	decrypted = crypto_aead_xchacha20poly1305_ietf_decrypt(
		ciphertext,
		aad=None,
		nonce=nonce,
		key=derived_key,
	)
	assert decrypted == plaintext


class DeviceAuthenticationTests(TestCase):
	def setUp(self):
		self.factory = APIRequestFactory()
		self.auth = DeviceAuthentication()
		self.device = Device.objects.create(
			device_identifier='device-auth-class-1',
			public_key='device_auth_class_public_key',
			public_key_algorithm='x25519',
		)

	def test_authenticate_returns_none_without_identifier_header(self):
		request = self.factory.get('/auth-test')
		self.assertIsNone(self.auth.authenticate(request))

	def test_authenticate_returns_anonymous_user_and_device_when_identifier_exists(self):
		request = self.factory.get('/auth-test', HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier)

		user, device = self.auth.authenticate(request)

		self.assertIsInstance(user, AnonymousUser)
		self.assertEqual(device, self.device)

	def test_authenticate_returns_none_for_unknown_device_identifier(self):
		request = self.factory.get('/auth-test', HTTP_X_DEVICE_IDENTIFIER='unknown-device')
		self.assertIsNone(self.auth.authenticate(request))

	def test_authenticate_header_returns_identifier_keyword(self):
		request = self.factory.get('/auth-test')
		self.assertEqual(self.auth.authenticate_header(request), 'X-Device-Identifier')


class DeviceTokenAuthenticationTests(TestCase):
	def setUp(self):
		self.factory = APIRequestFactory()
		self.auth = DeviceTokenAuthentication()
		self.device = Device.objects.create(
			device_identifier='device-token-auth-1',
			public_key='device_token_auth_public_key',
			public_key_algorithm='x25519',
		)

		self.raw_token = 'raw-device-token'
		self.token_hash = hashlib.sha256(self.raw_token.encode('utf-8')).hexdigest()
		self.auth_token = DeviceAuthToken.objects.create(
			device=self.device,
			token_hash=self.token_hash,
			expires_at=timezone.now() + timedelta(days=1),
		)

	def test_authenticate_returns_none_without_authorization_header(self):
		request = self.factory.get('/auth-test')
		self.assertIsNone(self.auth.authenticate(request))

	def test_authenticate_returns_none_for_non_bearer_scheme(self):
		request = self.factory.get('/auth-test', HTTP_AUTHORIZATION='Token abc123')
		self.assertIsNone(self.auth.authenticate(request))

	def test_authenticate_raises_for_invalid_bearer_header_shape(self):
		request = self.factory.get(
			'/auth-test',
			HTTP_AUTHORIZATION='Bearer too many parts',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		with self.assertRaises(exceptions.AuthenticationFailed):
			self.auth.authenticate(request)

	def test_authenticate_raises_for_invalid_or_expired_token(self):
		request = self.factory.get(
			'/auth-test',
			HTTP_AUTHORIZATION='Bearer not-a-real-token',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		with self.assertRaises(exceptions.AuthenticationFailed):
			self.auth.authenticate(request)

	def test_authenticate_raises_for_expired_token(self):
		expired_raw_token = 'expired-raw-device-token'
		expired_hash = hashlib.sha256(expired_raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=self.device,
			token_hash=expired_hash,
			expires_at=timezone.now() - timedelta(seconds=1),
		)

		request = self.factory.get(
			'/auth-test',
			HTTP_AUTHORIZATION=f'Bearer {expired_raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		with self.assertRaises(exceptions.AuthenticationFailed):
			self.auth.authenticate(request)

	def test_authenticate_raises_for_revoked_token(self):
		revoked_raw_token = 'revoked-raw-device-token'
		revoked_hash = hashlib.sha256(revoked_raw_token.encode('utf-8')).hexdigest()
		DeviceAuthToken.objects.create(
			device=self.device,
			token_hash=revoked_hash,
			expires_at=timezone.now() + timedelta(days=1),
			is_revoked=True,
		)

		request = self.factory.get(
			'/auth-test',
			HTTP_AUTHORIZATION=f'Bearer {revoked_raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		with self.assertRaises(exceptions.AuthenticationFailed):
			self.auth.authenticate(request)

	def test_authenticate_raises_when_identifier_does_not_match_token_owner(self):
		request = self.factory.get(
			'/auth-test',
			HTTP_AUTHORIZATION=f'Bearer {self.raw_token}',
			HTTP_X_DEVICE_IDENTIFIER='different-device-id',
		)

		with self.assertRaises(exceptions.AuthenticationFailed):
			self.auth.authenticate(request)

	def test_authenticate_returns_device(self):
		request = self.factory.get(
			'/auth-test',
			HTTP_AUTHORIZATION=f'Bearer {self.raw_token}',
			HTTP_X_DEVICE_IDENTIFIER=self.device.device_identifier,
		)

		user, device = self.auth.authenticate(request)

		self.assertIsInstance(user, AnonymousUser)
		self.assertEqual(device, self.device)
		self.assertEqual(request._device_auth_token, self.auth_token)

	def test_authenticate_header_returns_bearer(self):
		request = self.factory.get('/auth-test')
		self.assertEqual(self.auth.authenticate_header(request), 'Bearer')

	def test_authenticate_returns_none_when_device_identifier_header_missing(self):
		request = self.factory.get('/auth-test', HTTP_AUTHORIZATION=f'Bearer {self.raw_token}')
		self.assertIsNone(self.auth.authenticate(request))
