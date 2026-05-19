from rest_framework.schemas.openapi import AutoSchema
from .serializers import (
    AddDeviceToGroupResponseSerializer,
    AddDeviceToGroupSerializer,
    CreateGroupKeyEnvelopeResponseSerializer,
    CreateGroupKeyEnvelopeSerializer,
    CreateGroupSerializer,
    DeviceGroupKeyEnvelopeSerializer,
    DeleteEncryptedImageSerializer,
    DeleteGroupSerializer,
    DeviceLeavesGroupSerializer,
    DeviceAuthChallengeRequestSerializer,
    DeviceAuthChallengeResponseSerializer,
    DeviceEncryptedImageListResponseSerializer,
    DeviceAuthTokenRequestSerializer,
    DeviceAuthTokenResponseSerializer,
    GetDeviceGroupKeyEnvelopesSerializer,
    GroupDeviceSerializer,
    GetDeviceSelfStatusSerializer,
    ManagerGroupStatusSerializer,
    MainManagerGroupSerializer,
    RecipientEnvelopeSerializer,
    DeviceRegistrationSerializer,
    NotifyGroupSerializer,
    RegisterFCMDeviceSerializer,
    RemoveDeviceFromGroupSerializer,
    UpdateGroupSerializer,
    UploadEncryptedImageResponseSerializer,
    UserGroupSerializer,
)

class RequestResponseAutoSchema(AutoSchema):
    request_serializer_class = None
    response_serializer_class = None

    def get_request_serializer(self, path, method):
        if self.request_serializer_class is None:
            return None
        return self.request_serializer_class()

    def get_response_serializer(self, path, method):
        if self.response_serializer_class is None:
            return None
        return self.response_serializer_class()


def quota_error_response_schema():
    return {
        'type': 'object',
        'required': ['detail'],
        'properties': {
            'detail': {'type': 'string'},
            'quota': {
                'type': 'string',
                'nullable': True,
                'description': 'Quota key when the request is rejected by a limit check.',
            },
            'current': {
                'type': 'integer',
                'nullable': True,
                'description': 'Current usage value for the quota key.',
            },
            'maximum': {
                'type': 'integer',
                'nullable': True,
                'description': 'Configured maximum value for the quota key.',
            },
        },
    }
    
class DeviceAuthChallengeSchema(RequestResponseAutoSchema):
    request_serializer_class = DeviceAuthChallengeRequestSerializer
    response_serializer_class = DeviceAuthChallengeResponseSerializer

class DeviceAuthTokenSchema(RequestResponseAutoSchema):
    request_serializer_class = DeviceAuthTokenRequestSerializer
    response_serializer_class = DeviceAuthTokenResponseSerializer

class DeviceAuthRevokeSchema(AutoSchema):
    def get_request_serializer(self, path, method):
        return None

    def get_responses(self, path, method):
        return {
            '204': {
                'description': 'Device token revoked successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
        }


class DeviceLeavesGroupSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'deviceLeavesGroup'

    def get_request_serializer(self, path, method):
        return DeviceLeavesGroupSerializer()

    def get_responses(self, path, method):
        return {
            '204': {
                'description': 'Device left the group successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '404': {
                'description': 'Group not found or device is not part of this group.',
            },
        }


class GetDeviceGroupKeyEnvelopesSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'getDeviceGroupKeyEnvelopes'

    def get_request_serializer(self, path, method):
        return GetDeviceGroupKeyEnvelopesSerializer()

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        serializer = DeviceGroupKeyEnvelopeSerializer()
        response_schema = {
            'type': 'array',
            'items': self.map_serializer(serializer),
        }
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Group key envelopes for the authenticated device.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
        }

    def get_operation(self, path, method):
        operation = super().get_operation(path, method)
        operation['description'] = (
            'Returns wrapped group metadata keys for the authenticated device. Use group_shared '
            'for metadata any group device may decrypt. Use manager_roster for manager-only '
            'roster/admin metadata such as encrypted_member_name. Manager-owned devices may '
            'receive manager_roster envelopes; regular devices receive only group_shared.'
        )
        request_content = operation.get('requestBody', {}).get('content', {}).get('application/json')
        if request_content is not None:
            request_content['examples'] = {
                'all-available-scopes': {
                    'summary': 'Fetch all scopes available to this device',
                    'value': {
                        'groups': ['11111111-1111-1111-1111-111111111111'],
                    },
                },
                'manager-roster-only': {
                    'summary': 'Fetch only manager-only roster/admin keys',
                    'value': {
                        'groups': ['11111111-1111-1111-1111-111111111111'],
                        'scopes': ['manager_roster'],
                    },
                },
            }

        response_content = operation.get('responses', {}).get('200', {}).get('content', {}).get('application/json')
        if response_content is not None:
            response_content['examples'] = {
                'group-shared-envelope': {
                    'summary': 'Shared metadata key visible to all group devices',
                    'value': [
                        {
                            'group': '11111111-1111-1111-1111-111111111111',
                            'scope': 'group_shared',
                            'key_wrap_algorithm': 'x25519-xsalsa20-poly1305',
                            'recipient_key_fingerprint': 'a' * 64,
                            'encrypted_group_key': 'YmFzZTY0LWdyb3VwLXNoYXJlZC1rZXk=',
                        },
                    ],
                },
                'manager-roster-envelope': {
                    'summary': 'Manager-only roster/admin key',
                    'value': [
                        {
                            'group': '11111111-1111-1111-1111-111111111111',
                            'scope': 'manager_roster',
                            'key_wrap_algorithm': 'x25519-xsalsa20-poly1305',
                            'recipient_key_fingerprint': 'b' * 64,
                            'encrypted_group_key': 'YmFzZTY0LW1hbmFnZXItcm9zdGVyLWtleQ==',
                        },
                    ],
                },
            }
        return operation


class ListEncryptedImagesSchema(RequestResponseAutoSchema):
    request_serializer_class = None
    response_serializer_class = DeviceEncryptedImageListResponseSerializer

    def get_operation_id(self, path, method):
        return 'listEncryptedImages'

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        response_serializer = self.get_response_serializer(path, method)
        response_schema = self.get_reference(response_serializer)
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Paginated list of encrypted images grouped by group and day.',
            },
            '400': {'description': 'Invalid request parameters.'},
            '401': {'description': 'Authentication credentials were not provided.'},
        }

    def get_operation(self, path, method):
        operation = super().get_operation(path, method)
        operation['parameters'] = operation.get('parameters', []) + [
            {
                'name': 'cursor',
                'in': 'query',
                'required': False,
                'schema': {'type': 'string'},
                'description': 'Pagination cursor returned by a previous response.',
            },
            {
                'name': 'limit',
                'in': 'query',
                'required': False,
                'schema': {'type': 'integer'},
                'description': 'Maximum number of images to return per page.',
            },
        ]
        return operation

# Minimal schema for the encrypted image blob download endpoint
class DownloadEncryptedImageBlobSchema(RequestResponseAutoSchema):
    request_serializer_class = None
    response_serializer_class = None

    def get_operation_id(self, path, method):
        return 'downloadEncryptedImageBlob'

    def get_responses(self, path, method):
        return {
            '200': {
                'description': 'Binary encrypted image blob',
                'content': {
                    'application/octet-stream': {
                        'schema': {'type': 'string', 'format': 'binary'}
                    }
                }
            },
            '401': {'description': 'Authentication credentials were not provided.'},
            '404': {'description': 'Encrypted image not found.'},
        }


class AddDeviceToGroupSchema(RequestResponseAutoSchema):
    request_serializer_class = AddDeviceToGroupSerializer
    response_serializer_class = AddDeviceToGroupResponseSerializer

    def get_operation_id(self, path, method):
        return 'addDeviceToGroup'

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        response_schema = self.get_reference(self.get_response_serializer(path, method))
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Device was already linked to the group.',
            },
            '201': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Device linked to the group successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'description': 'Only main managers can perform this action.',
            },
            '404': {
                'description': 'Group not found or device not found.',
            },
        }


class CreateGroupSchema(RequestResponseAutoSchema):
    request_serializer_class = CreateGroupSerializer
    response_serializer_class = MainManagerGroupSerializer

    def get_operation_id(self, path, method):
        return 'createGroup'

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        response_schema = self.get_reference(self.get_response_serializer(path, method))
        return {
            '201': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Group created successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'content': {
                    ct: {'schema': quota_error_response_schema()}
                    for ct in self.response_media_types
                },
                'description': 'Permission denied or max_groups limit reached.',
            },
        }


class RegisterDeviceSchema(RequestResponseAutoSchema):
    request_serializer_class = DeviceRegistrationSerializer

    def get_operation_id(self, path, method):
        return 'registerDevice'

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        response_schema = {
            'type': 'object',
            'required': ['device_identifier', 'public_key_algorithm', 'device_created'],
            'properties': {
                'device_identifier': {'type': 'string'},
                'public_key_algorithm': {'type': 'string'},
                'device_created': {'type': 'boolean'},
            },
        }
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Device already existed and was updated or reused.',
            },
            '201': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Device registered successfully.',
            },
            '400': {
                'description': 'Request validation failed.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'content': {
                    ct: {'schema': quota_error_response_schema()}
                    for ct in self.response_media_types
                },
                'description': 'Permission denied or max_devices limit reached.',
            },
        }


class CreateGroupKeyEnvelopeSchema(RequestResponseAutoSchema):
    request_serializer_class = CreateGroupKeyEnvelopeSerializer
    response_serializer_class = CreateGroupKeyEnvelopeResponseSerializer

    def get_operation_id(self, path, method):
        return 'createGroupKeyEnvelope'

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        response_schema = self.get_reference(self.get_response_serializer(path, method))
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Group key envelopes updated successfully.',
            },
            '201': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Group key envelopes created successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'description': 'Only main managers can perform this action.',
            },
            '404': {
                'description': 'Group not found.',
            },
        }

    def get_operation(self, path, method):
        operation = super().get_operation(path, method)
        operation['description'] = (
            'Creates or updates wrapped group metadata keys for one scope. Use group_shared for '
            'metadata that any group device may decrypt. Use manager_roster for manager-only '
            'roster/admin metadata such as encrypted_member_name. manager_roster envelopes may '
            'only target devices owned by a manager or main manager of the group.'
        )
        request_content = operation.get('requestBody', {}).get('content', {}).get('application/json')
        if request_content is not None:
            request_content['examples'] = {
                'group-shared': {
                    'summary': 'Distribute the shared group metadata key to group devices',
                    'value': {
                        'group': '11111111-1111-1111-1111-111111111111',
                        'scope': 'group_shared',
                        'key_envelopes': [
                            {
                                'recipient_device_identifier': 'device-a',
                                'key_wrap_algorithm': 'x25519-xsalsa20-poly1305',
                                'recipient_key_fingerprint': 'a' * 64,
                                'encrypted_group_key': 'YmFzZTY0LWdyb3VwLXNoYXJlZC1rZXk=',
                            },
                        ],
                    },
                },
                'manager-roster': {
                    'summary': 'Distribute the manager-only roster/admin key',
                    'value': {
                        'group': '11111111-1111-1111-1111-111111111111',
                        'scope': 'manager_roster',
                        'key_envelopes': [
                            {
                                'recipient_device_identifier': 'manager-device-a',
                                'key_wrap_algorithm': 'x25519-xsalsa20-poly1305',
                                'recipient_key_fingerprint': 'b' * 64,
                                'encrypted_group_key': 'YmFzZTY0LW1hbmFnZXItcm9zdGVyLWtleQ==',
                            },
                        ],
                    },
                },
            }
        return operation


class UpdateGroupSchema(RequestResponseAutoSchema):
    request_serializer_class = UpdateGroupSerializer
    response_serializer_class = MainManagerGroupSerializer

    def get_operation_id(self, path, method):
        return 'updateGroup'

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        response_schema = self.get_reference(self.get_response_serializer(path, method))
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Group updated successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'description': 'Only main managers can perform this action.',
            },
            '404': {
                'description': 'Group not found.',
            },
        }


class DeleteGroupSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'deleteGroup'

    def get_request_serializer(self, path, method):
        return DeleteGroupSerializer()

    def get_operation(self, path, method):
        operation = super().get_operation(path, method)
        request_serializer = self.get_request_serializer(path, method)
        if request_serializer is not None:
            operation['requestBody'] = {
                'content': {
                    content_type: {'schema': self.map_serializer(request_serializer)}
                    for content_type in self.map_renderers(path, method)
                },
                'required': True,
            }
        operation['responses'] = self.get_responses(path, method)
        return operation

    def get_responses(self, path, method):
        return {
            '204': {
                'description': 'Group deleted successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'description': 'Only main managers can perform this action.',
            },
            '404': {
                'description': 'Group not found.',
            },
        }


class DeleteEncryptedImageSchema(AutoSchema):
    def get_operation_id(self, path, method):
        if method == 'DELETE':
            return 'deleteEncryptedImage'
        return 'deleteEncryptedImagePost'

    def get_request_serializer(self, path, method):
        return DeleteEncryptedImageSerializer()

    def get_operation(self, path, method):
        operation = super().get_operation(path, method)
        request_serializer = self.get_request_serializer(path, method)
        if request_serializer is not None:
            operation['requestBody'] = {
                'content': {
                    content_type: {'schema': self.map_serializer(request_serializer)}
                    for content_type in self.map_renderers(path, method)
                },
                'required': True,
            }
        operation['responses'] = self.get_responses(path, method)
        return operation

    def get_responses(self, path, method):
        return {
            '204': {
                'description': 'Encrypted image deleted successfully.',
            },
            '400': {
                'description': 'Missing or invalid delete parameters.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'description': 'Only group managers or group devices can perform this action.',
            },
            '404': {
                'description': 'Group not found or encrypted image not found.',
            },
        }


class RemoveDeviceFromGroupSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'removeDeviceFromGroup'

    def get_request_serializer(self, path, method):
        return RemoveDeviceFromGroupSerializer()

    def get_responses(self, path, method):
        return {
            '204': {
                'description': 'Device removed from the group successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'description': 'Only main managers can perform this action.',
            },
            '404': {
                'description': 'Group not found, device not found, or device is not part of this group.',
            },
        }


class ListGroupDevicesSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'getMainManagerGroupDevices'

    def get_request_serializer(self, path, method):
        return None

    def get_operation(self, path, method):
        operation = super().get_operation(path, method)
        operation['parameters'] = operation.get('parameters', []) + [
            {
                'name': 'group',
                'in': 'query',
                'required': True,
                'description': 'UUID of the group whose devices should be listed.',
                'schema': {
                    'type': 'string',
                    'format': 'uuid',
                },
            },
        ]
        operation['responses'] = self.get_responses(path, method)
        return operation

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        serializer = GroupDeviceSerializer()
        response_schema = {
            'type': 'array',
            'items': self.map_serializer(serializer),
        }
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Devices linked to the specified group.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'description': 'Only main managers can perform this action.',
            },
            '404': {
                'description': 'Group not found.',
            },
        }


class GetOwnGroupDevicesSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'getManagerGroupDevices'

    def get_request_serializer(self, path, method):
        return None

    def get_operation(self, path, method):
        operation = super().get_operation(path, method)
        operation['parameters'] = operation.get('parameters', []) + [
            {
                'name': 'group',
                'in': 'query',
                'required': True,
                'description': 'UUID of the group whose authenticated user-owned devices should be listed.',
                'schema': {
                    'type': 'string',
                    'format': 'uuid',
                },
            },
        ]
        operation['responses'] = self.get_responses(path, method)
        return operation

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        serializer = GroupDeviceSerializer()
        response_schema = {
            'type': 'array',
            'items': self.map_serializer(serializer),
        }
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Devices owned by the authenticated user and linked to the specified group.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '404': {
                'description': 'Group not found.',
            },
        }
        
class GetDeviceSelfStatusSchema(RequestResponseAutoSchema):
    request_serializer_class = None
    response_serializer_class = GetDeviceSelfStatusSerializer
    
    def get_operation_id(self, path, method):
        return 'getDeviceSelfStatus'
    
    def get_responses(self, path, method):

        self.response_media_types = self.map_renderers(path, method)

        serializer = self.get_response_serializer(path, method)
        item_schema = self.get_reference(serializer)

        response_schema = item_schema
        status_code = '201' if method == 'POST' else '200'
        return {
            status_code: {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                # description is a mandatory property,
                # https://github.com/OAI/OpenAPI-Specification/blob/master/versions/3.0.2.md#responseObject
                # TODO: put something meaningful into it
                'description': ""
            }
        }
        
        
class GetMainManagerGroupsSchema(RequestResponseAutoSchema):
    request_serializer_class = None
    response_serializer_class = MainManagerGroupSerializer


class GetManagerGroupsSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'getManagerGroups'

    def get_request_serializer(self, path, method):
        return None

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        serializer = ManagerGroupStatusSerializer()
        response_schema = {
            'type': 'array',
            'items': self.map_serializer(serializer),
        }
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Groups for the authenticated manager account.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
        }


class UploadEncryptedImageSchema(RequestResponseAutoSchema):
    request_serializer_class = None
    response_serializer_class = UploadEncryptedImageResponseSerializer

    def get_operation_id(self, path, method):
        return 'uploadEncryptedImage'

    def get_request_body(self, path, method):
        recipient_envelope_schema = self.map_serializer(RecipientEnvelopeSerializer())
        request_schema = {
            'type': 'object',
            'required': [
                'encrypted_blob',
                'group',
                'payload_nonce',
                'recipient_envelopes',
            ],
            'properties': {
                'encrypted_blob': {
                    'type': 'string',
                    'format': 'binary',
                    'description': 'Encrypted ciphertext payload file.',
                },
                'encrypted_caption': {
                    'type': 'string',
                    'description': 'Optional encrypted caption.',
                },
                'group': {
                    'type': 'string',
                    'format': 'uuid',
                },
                'crypto_version': {
                    'type': 'integer',
                    'minimum': 1,
                    'maximum': 32767,
                    'default': 1,
                },
                'encryption_algorithm': {
                    'type': 'string',
                    'maxLength': 32,
                    'default': 'xchacha20poly1305',
                },
                'payload_nonce': {
                    'type': 'string',
                    'description': 'Base64-encoded payload nonce.',
                },
                'recipient_envelopes': {
                    'type': 'array',
                    'items': recipient_envelope_schema,
                    'description': 'Recipient envelope records encoded as JSON in the multipart field.',
                },
                'expires_at': {
                    'type': 'string',
                    'format': 'date-time',
                    'nullable': True,
                },
                'client_ciphertext_hash_sha256': {
                    'type': 'string',
                    'maxLength': 64,
                    'pattern': '^[a-f0-9]{64}$',
                },
            },
        }
        return {
            'content': {
                'multipart/form-data': {
                    'schema': request_schema,
                    'encoding': {
                        'recipient_envelopes': {
                            'contentType': 'application/json',
                        },
                    },
                },
            },
            'required': True,
        }

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        response_schema = self.get_reference(self.get_response_serializer(path, method))
        return {
            '201': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'Encrypted image uploaded successfully.',
            },
            '400': {
                'description': 'Request validation failed.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'content': {
                    ct: {'schema': quota_error_response_schema()}
                    for ct in self.response_media_types
                },
                'description': 'Permission denied or max_images limit reached.',
            },
            '404': {
                'description': 'Group not found.',
            },
        }


class GetDeviceGroupsSchema(RequestResponseAutoSchema):
    request_serializer_class = None
    response_serializer_class = UserGroupSerializer


class HealthSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'getStatus'

    def get_request_serializer(self, path, method):
        return None

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        return {
            '200': {
                'description': 'Service is healthy.',
                'content': {
                    ct: {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'status': {'type': 'string', 'example': 'ok'},
                                'organization': {'type': 'string'},
                            },
                        }
                    }
                    for ct in self.response_media_types
                },
            },
        }


class RegisterFCMDeviceSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'registerFCMDevice'

    def get_request_serializer(self, path, method):
        return RegisterFCMDeviceSerializer()

    def get_responses(self, path, method):
        return {
            '200': {
                'description': 'FCM registration token updated for this device.',
            },
            '201': {
                'description': 'FCM device registered for this device.',
            },
            '400': {
                'description': 'Invalid request body.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
        }


class DeregisterFCMDeviceSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'deregisterFCMDevice'

    def get_request_serializer(self, path, method):
        return None

    def get_responses(self, path, method):
        return {
            '204': {
                'description': 'FCM device deregistered successfully.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '404': {
                'description': 'No FCM device registration found for this device.',
            },
        }


class NotifyGroupSchema(AutoSchema):
    def get_operation_id(self, path, method):
        return 'notifyGroup'

    def get_request_serializer(self, path, method):
        return NotifyGroupSerializer()

    def get_responses(self, path, method):
        self.response_media_types = self.map_renderers(path, method)
        response_schema = {
            'type': 'object',
            'properties': {
                'notified_count': {'type': 'integer'},
                'skipped_count': {'type': 'integer'},
            },
        }
        return {
            '200': {
                'content': {
                    ct: {'schema': response_schema}
                    for ct in self.response_media_types
                },
                'description': 'FCM notification dispatched to group members.',
            },
            '400': {
                'description': 'Request validation failed.',
            },
            '401': {
                'description': 'Authentication credentials were not provided.',
            },
            '403': {
                'description': 'Only group managers can perform this action.',
            },
        }