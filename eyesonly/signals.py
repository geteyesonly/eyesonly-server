from django.db.models.signals import post_delete
from django.dispatch import receiver

from .models import Device, EncryptedImage, GroupDevices


@receiver(post_delete, sender=GroupDevices)
def delete_orphan_device(sender, instance, **kwargs):
    device_id = instance.device_id
    if not device_id:
        return

    # Keep user-owned devices registered even when they currently belong to no groups.
    if GroupDevices.objects.filter(device_id=device_id).exists():
        return

    Device.objects.filter(pk=device_id, owner_user__isnull=True).delete()


@receiver(post_delete, sender=EncryptedImage)
def delete_encrypted_image_blob(sender, instance, **kwargs):
    if not instance.encrypted_blob:
        return

    instance.encrypted_blob.delete(save=False)
    
    
    