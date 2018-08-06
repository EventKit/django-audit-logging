# -*- coding: utf-8 -*-
#########################################################################
#
# Copyright (C) 2017 Boundless Spatial
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################

from importlib import import_module
import json
from logging import getLogger
from time import gmtime, strftime

from django.conf import settings

from audit_logging.audit_settings import AUDIT_LOGFILE_LOCATION
import threading


logger = getLogger(__name__)
audit_logging_thread_local = threading.local()


def log_event(event=None, resource_type='file', resource_uuid=None, user_details=None):
    try:
        from audit_logging.models import AuditEvent
        username = user_details.get('username') if user_details else None
        is_superuser = user_details.get('is_superuser') if user_details else None
        is_staff = user_details.get('is_staff') if user_details else None
        AuditEvent.objects.create(
            event=event, resource_type=resource_type, resource_uuid=resource_uuid, username=username,
            superuser=is_superuser, staff=is_staff
        )
    except Exception as ex:
        pass


def configure_audit_models():
    """ Imports models specified in settings variable AUDIT_MODELS.
        AUDIT_MODELS is a list with elements of the form (<dotted-path-to-model>, <resource-type>), both of which are
            strings.
        @return: {<resource-type>: <model>, ...}
    """
    cached_return_value = getattr(configure_audit_models, 'cached_return_value', None)
    if cached_return_value is not None:
        return cached_return_value

    audit_model_specs = getattr(settings, 'AUDIT_MODELS', [])
    if not audit_model_specs:
        logger.warn('No models specified for audit, you probably forgot to set AUDIT_MODELS.')

    audit_model_lookup = {}
    logger.info('Registering models for auditing:')
    for dotted_path, resource_type in audit_model_specs:
        logger.info('{} recorded as {}'.format(dotted_path, resource_type))
        module_dotted_path, model_name = dotted_path.rsplit('.', 1)
        model_module = import_module(module_dotted_path)
        model_to_audit = getattr(model_module, model_name)
        audit_model_lookup.update({resource_type: model_to_audit})

    configure_audit_models.cached_return_value = audit_model_lookup
    return audit_model_lookup


def get_audit_crud_dict(instance, event):
    """ Get details for instance and return as dictionary
        return None if the model isn't configured for auditing.
    """
    audit_model_lookup = configure_audit_models()
    d = {}
    for idx, item in enumerate(audit_model_lookup.values()):
        if isinstance(instance, item):
            # populate resource details from instance
            d['resource'] = get_resource(instance)
            d['event'] = event
            d['event_time_gmt'] = get_time_gmt()
            break

    logger.debug('CRUD details for {}: {}'.format(instance, d).encode('utf-8'))

    return d


def get_audit_login_dict(request, user, event):
    """get user login details and return as user_details dictionary"""
    d = {
        "user_details": {
            "username": getattr(user, user.USERNAME_FIELD),
            "ip": get_client_ip(request),
            "superuser": user.is_superuser,
            "staff": user.is_staff,
            "fullname": user.get_full_name() or None,
            "email": user.email or None
        },
        "event": event,
        "event_time_gmt": get_time_gmt()
    }
    return d


def get_time_gmt():
    """get current datetime as gmt"""
    return strftime("%Y-%m-%d %H:%M:%S", gmtime())


def get_resource(instance):
    """get instance details and return as resource dictonary"""
    # Check that instance is one of the models that's configured for logging
    audit_model_lookup = configure_audit_models()
    resource_type = None
    for resource_type, model_type in list(audit_model_lookup.items()):
        if isinstance(instance, model_type):
            resource_type = resource_type
            break

    # Not one of the models configured for logging
    if resource_type is None:
        return {}

    # Check for existence of each of these fields in order on instance until one is found or all are tried.
    username_fields = ['user', 'owner', ]
    username = None
    for ufield in username_fields:
        user = getattr(instance, ufield, None)
        if user is not None:
            username = getattr(user, 'username', None)
            if username is not None:
                break

    id = None
    id_fields = ['uuid', 'uid', 'id']
    for id_field in id_fields:
        id = getattr(instance, id_field, None)
        if id is not None:
            break

    # create resource dict
    resource = {
       "id": id,
       "type": resource_type,
       "username": username,
    }
    return resource


def get_user_crud_details(contact):
    """get user crud details and return as user_details dictionary"""
    user_details = {
        "username": contact.username,
        "superuser": contact.is_superuser,
        "staff": contact.is_staff,
        "fullname": contact.get_full_name() or None,
        "email": contact.email or None
    }
    return user_details


def write_entry(d):
    """write dictionary to json file output"""
    with open(AUDIT_LOGFILE_LOCATION, 'a') as j:
        json.dump(d, j, sort_keys=True)
        j.write('\n')
        j.close()


def get_client_ip(request):
    """get client ip from reguest"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
