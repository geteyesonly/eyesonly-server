from .models import GroupDevices

def can_delete_encrypted_image(encrypted_image, user=None, device=None):
    if user:
        # if the user is a manager of the group, they can delete the image
        if encrypted_image.group.managers.filter(id=user.id).exists():
            return True
    if device:
        group = encrypted_image.group
        # if the device is associated with the group and has delete permissions, it can delete the image
        if GroupDevices.objects.filter(group=group, device=device, can_delete_images=True).exists():
            return True
    return False