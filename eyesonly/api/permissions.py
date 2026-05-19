from uuid import UUID

from rest_framework import permissions

from eyesonly.models import Group, GroupDevices, ManagerRole


class IsGroupMainManager(permissions.BasePermission):
    """
    Permission class that checks if the user is a main_manager in the specified group.
    
    The group UUID must be provided in request.data['group'] (POST/PUT) or 
    request.query_params['group'] (GET).
    """
    message = 'Only main managers can perform this action.'

    def has_permission(self, request, view):
        if not getattr(request.user, 'is_authenticated', False):
            return False

        # Get group UUID from POST/PUT data or query params
        group_uuid = request.data.get('group') if hasattr(request, 'data') else None
        if not group_uuid:
            group_uuid = request.query_params.get('group')

        if not group_uuid:
            return False

        # Validate UUID format
        try:
            UUID(str(group_uuid))
        except (ValueError, TypeError):
            return False

        # Check if group exists
        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            # Let the view handle 404 for non-existent groups
            return True

        # Check if user is a main_manager in this group
        return ManagerRole.objects.filter(
            manager=request.user,
            group=group,
            role='main_manager',
        ).exists()


class IsGroupManager(permissions.BasePermission):
    """
    Permission class that checks if the user is a manager (manager or
    main_manager) in the specified group.

    The group UUID must be provided in request.data['group'] (POST/PUT) or
    request.query_params['group'] (GET).
    """
    message = 'Only group managers can perform this action.'

    def has_permission(self, request, view):
        if not getattr(request.user, 'is_authenticated', False):
            return False

        # Get group UUID from POST/PUT data or query params
        group_uuid = request.data.get('group') if hasattr(request, 'data') else None
        if not group_uuid:
            group_uuid = request.query_params.get('group')

        if not group_uuid:
            return False

        # Validate UUID format
        try:
            UUID(str(group_uuid))
        except (ValueError, TypeError):
            return False

        # Check if group exists
        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            # Let the view handle 404 for non-existent groups
            return True

        # Check if user is manager or main_manager in this group
        return ManagerRole.objects.filter(
            manager=request.user,
            group=group,
            role__in=['main_manager', 'manager'],
        ).exists()


class IsGroupDevice(permissions.BasePermission):
    """
    Permission class that checks if the authenticated device belongs to the
    specified group.

    The group UUID must be provided in request.data['group'] (POST/PUT) or
    request.query_params['group'] (GET).
    """
    message = 'Only devices that belong to this group can perform this action.'

    def has_permission(self, request, view):
        # DeviceTokenAuthentication stores the authenticated device in request.auth.
        device = getattr(request, 'auth', None)
        if device is None:
            return False

        # Get group UUID from POST/PUT data or query params.
        group_uuid = request.data.get('group') if hasattr(request, 'data') else None
        if not group_uuid:
            group_uuid = request.query_params.get('group')

        if not group_uuid:
            return False

        # Validate UUID format.
        try:
            UUID(str(group_uuid))
        except (ValueError, TypeError):
            return False

        # Check if group exists.
        try:
            group = Group.objects.get(uuid=group_uuid)
        except Group.DoesNotExist:
            # Let the view handle 404 for non-existent groups.
            return True

        # Ensure the authenticated device is linked to this group.
        return GroupDevices.objects.filter(group=group, device=device).exists()


class IsGroupManagerOrDevice(permissions.BasePermission):
    """
    Permission class that allows either:
    - a group manager (manager/main_manager), or
    - a device that belongs to the group.
    """
    message = 'Only group managers or group devices can perform this action.'

    def has_permission(self, request, view):
        return IsGroupManager().has_permission(request, view) or IsGroupDevice().has_permission(request, view)
