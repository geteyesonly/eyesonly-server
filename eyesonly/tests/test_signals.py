from django.test import TestCase

from django.contrib.auth import get_user_model

from eyesonly.models import Device, Group, GroupDevices

User = get_user_model()

class TestDeviceOrphanCleanupSignal(TestCase):
    def test_device_deleted_when_last_group_link_removed(self):
        group = Group.objects.create(encrypted_name='Signal Group One', name_nonce=b'0' * 24)
        device = Device.objects.create(
            device_identifier='device-signal-delete',
            public_key='public_key_material_signal_delete',
            public_key_algorithm='x25519',
        )
        link = GroupDevices.objects.create(group=group, device=device, can_delete_images=False)

        link.delete()
        self.assertFalse(Device.objects.filter(id=device.id).exists())

    def test_owned_device_not_deleted_when_last_group_link_removed(self):
        owner = User.objects.create_user(username='signal-owner', password='testpass')
        group = Group.objects.create(encrypted_name='Signal Group Owned', name_nonce=b'1' * 24)
        device = Device.objects.create(
            device_identifier='device-signal-owned',
            owner_user=owner,
            public_key='public_key_material_signal_owned',
            public_key_algorithm='x25519',
        )
        link = GroupDevices.objects.create(group=group, device=device, can_delete_images=False)

        link.delete()

        self.assertTrue(Device.objects.filter(id=device.id).exists())

    def test_device_not_deleted_when_other_group_links_exist(self):
        group_one = Group.objects.create(encrypted_name='Signal Group Two A', name_nonce=b'2' * 24)
        group_two = Group.objects.create(encrypted_name='Signal Group Two B', name_nonce=b'3' * 24)
        device = Device.objects.create(
            device_identifier='device-signal-keep',
            public_key='public_key_material_signal_keep',
            public_key_algorithm='x25519',
        )
        link_one = GroupDevices.objects.create(group=group_one, device=device, can_delete_images=False)
        GroupDevices.objects.create(group=group_two, device=device, can_delete_images=False)

        link_one.delete()
        self.assertTrue(Device.objects.filter(id=device.id).exists())