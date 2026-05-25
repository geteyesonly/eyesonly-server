from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group as AuthGroup
from django.contrib.admin.sites import NotRegistered
from django.conf import settings
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from fcm_django.models import FCMDevice

admin.site.site_header = "Eyes Only Administration"
admin.site.site_title = "Eyes Only Admin"
admin.site.index_title = "Manage Eyes Only"

from .models import (
	Device,
	DeviceAuthChallenge,
	EncryptedImage,
	Group as AppGroup,
	GroupDevices,
	GroupKeyEnvelope,
	ManagerRole,
	Organization,
	RecipientEnvelope,
)

User = get_user_model()

User._meta.verbose_name = "Manager"
User._meta.verbose_name_plural = "Manager"

try:
	admin.site.unregister(AuthGroup)
except NotRegistered:
	pass

@admin.register(ManagerRole)
class ManagerRoleAdmin(admin.ModelAdmin):
	list_display = ('id', 'manager', 'group', 'role')
	list_filter = ('role', 'group')
	search_fields = ('manager__username', 'manager__email', 'group__uuid', 'group__encrypted_name')
	ordering = ('-id',)
 
 
@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
	list_display = (
		'id',
		'device_identifier',
		'owner_user',
		'public_key_algorithm',
		'public_key_fingerprint',
		'fcm_status',
	)
	search_fields = ('device_identifier', 'owner_user__username', 'owner_user__email', 'public_key_fingerprint')
	ordering = ('-id',)
	readonly_fields = ('public_key_fingerprint', 'fcm_registration_id', 'fcm_type', 'fcm_active')
	exclude = ('public_key',)

	@admin.display(description='FCM')
	def fcm_status(self, obj):
		if obj.fcm_device_id is None:
			return '—'
		return 'active' if obj.fcm_device.active else 'inactive'

	@admin.display(description='FCM registration token')
	def fcm_registration_id(self, obj):
		if obj.fcm_device_id is None:
			return '—'
		return obj.fcm_device.registration_id

	@admin.display(description='FCM device type')
	def fcm_type(self, obj):
		if obj.fcm_device_id is None:
			return '—'
		return obj.fcm_device.type

	@admin.display(description='FCM active')
	def fcm_active(self, obj):
		if obj.fcm_device_id is None:
			return '—'
		return obj.fcm_device.active


if settings.DEBUG == False:
	try:
		admin.site.unregister(OutstandingToken)
	except NotRegistered:
		pass

	try:
		admin.site.unregister(BlacklistedToken)
	except NotRegistered:
		pass
	try:
		admin.site.unregister(FCMDevice)
	except NotRegistered:
		pass


if settings.DEBUG == True:
    
	@admin.register(AppGroup)
	class GroupAdmin(admin.ModelAdmin):
		list_display = ('id', 'uuid', 'encrypted_name')
		search_fields = ('encrypted_name', 'uuid')
		ordering = ('-id',)
    
	@admin.register(GroupDevices)
	class GroupDevicesAdmin(admin.ModelAdmin):
		list_display = ('id', 'group', 'device', 'encrypted_member_name', 'can_delete_images')
		list_filter = ('can_delete_images', 'group')
		search_fields = ('group__uuid', 'group__encrypted_name', 'device__device_identifier')
		ordering = ('-id',)

	@admin.register(DeviceAuthChallenge)
	class DeviceAuthChallengeAdmin(admin.ModelAdmin):
		list_display = ('device', 'expires_at', 'is_used')
		search_fields = ('device__device_identifier',)
		list_filter = ('is_used', 'expires_at')
		exclude = ('challenge_hash',)
  
  
	@admin.register(GroupKeyEnvelope)
	class GroupKeyEnvelopeAdmin(admin.ModelAdmin):
		list_display = (
			'id',
			'group',
			'recipient_device',
			'scope',
			'key_wrap_algorithm',
			'recipient_key_fingerprint',
		)
		list_filter = ('scope', 'key_wrap_algorithm', 'group', 'recipient_device')
		search_fields = ('group__uuid', 'recipient_device__device_identifier', 'recipient_key_fingerprint')
		ordering = ('-id',)
		readonly_fields = ()
  

	@admin.register(RecipientEnvelope)
	class RecipientEnvelopeAdmin(admin.ModelAdmin):
		list_display = (
			'id',
			'encrypted_image',
			'recipient_device',
			'key_wrap_algorithm',
			'recipient_key_fingerprint',
		)
		list_filter = ('key_wrap_algorithm', 'recipient_device')
		search_fields = ('encrypted_image__id', 'recipient_device__device_identifier', 'recipient_key_fingerprint')
		ordering = ('-id',)
		readonly_fields = ()
  
	@admin.register(Organization)
	class OrganizationAdmin(admin.ModelAdmin):
		list_display = ('id', 'name')
		search_fields = ('name',)


	@admin.register(EncryptedImage)
	class EncryptedImageAdmin(admin.ModelAdmin):
		list_display = (
			'id',
			'group',
			'uploaded_by',
			'crypto_version',
			'encryption_algorithm',
			'ciphertext_hash_sha256',
			'expires_at',
			'created_at',
		)
		list_filter = ('group', 'encryption_algorithm', 'crypto_version', 'created_at', 'expires_at')
		search_fields = ('=id', 'group__uuid', 'uploaded_by__username', 'uploaded_by__email', 'ciphertext_hash_sha256')
		ordering = ('-created_at',)
		readonly_fields = (
			'group',
			'uploaded_by',
			'crypto_version',
			'encryption_algorithm',
			'ciphertext_hash_sha256',
			'expires_at',
			'created_at',
		)
		exclude = ('encrypted_blob', 'encrypted_caption', 'payload_nonce')


	