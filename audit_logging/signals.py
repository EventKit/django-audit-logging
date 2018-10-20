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

import logging

from django.contrib.auth import signals as auth_signals, get_user_model
from django.db.models import signals as models_signals
from .models import AuditEvent
from audit_logging.audit_settings import AUDIT_TO_FILE
from audit_logging import version as audit_logging_version
from audit_logging.utils import (
    get_audit_crud_dict, get_audit_login_dict, get_time_gmt, write_entry, audit_logging_thread_local
)

logger = logging.getLogger(__name__)

def log_event(instance, event=None):
    if isinstance(instance, AuditEvent):
        return

    try:
        d = get_audit_crud_dict(instance, event)
        if d:
            if AUDIT_TO_FILE:
                write_entry(d)
            from audit_logging.utils import log_event
            user_details = getattr(audit_logging_thread_local, 'user_details', {})
            logger.debug(
                'Got user_details from audit_logging_thread_local: {}'.format(str(user_details).encode('utf-8')))
            resource = d.get('resource')
            resource_type = resource.get('type', 'unknown') if resource else 'unknown'
            resource_uuid = resource.get('id', 'unknown') if resource else 'unknown'
            log_event(event=event, resource_type=resource_type, resource_uuid=resource_uuid, user_details=user_details)
        else:
            logger.debug('get_audit_crud_dict() returned nothing (normal if {} not in AUDIT_MODELS)'.format(str(instance).encode('utf-8')))
    except Exception as ex:
        logger.exception('Exception during audit event.')


def post_save(sender, instance, created, raw, using, update_fields, **kwargs):
    """
    signal to catch save signals (create and update) and log them in
    the audit log.
    """
    if isinstance(instance, AuditEvent):
        return
    logger.debug('Received post_save signal for: {} ({})'.format(str(instance).encode('utf-8'), str(type(instance)).encode('utf-8')))

    if created:
        event = 'create'
    else:
        event = 'update'
    log_event(instance, event)


def post_delete(sender, instance, using, **kwargs):
    """
    signal to catch delete signals and log them in the audit log
    """
    if isinstance(instance, AuditEvent):
        return
    logger.debug('Received post_delete signal for: {} ({})'.format(str(instance).encode('utf-8'), str(type(instance)).encode('utf-8')))


    log_event(instance, 'delete')


def user_logged_in(sender, request, user, **kwargs):
    """
    signal to catch logins and log them in the audit log
    """
    try:
        event = 'login'
        d = get_audit_login_dict(request, user, event)
        if d:
            if AUDIT_TO_FILE:
                write_entry(d)
            login_event = AuditEvent(
                event=event,
                username=d['user_details']['username'],
                ip=d['user_details']['ip'],
                email=d['user_details']['email'],
                fullname=d['user_details']['fullname'],
                superuser=d['user_details']['superuser'],
                staff=d['user_details']['staff'],
            )
            login_event.save()
    except:
        pass


def user_logged_out(sender, request, user, **kwargs):
    """
    signal to catch user log outs and log them in the audit log
    """
    try:
        event = 'logout'
        d = get_audit_login_dict(request, user, event)
        if d:
            if AUDIT_TO_FILE:
                write_entry(d)
            login_event = AuditEvent(
                event=event,
                username=d['user_details']['username'],
                ip=d['user_details']['ip'],
                email=d['user_details']['email'],
                fullname=d['user_details']['fullname'],
                superuser=d['user_details']['superuser'],
                staff=d['user_details']['staff'],
            )
            login_event.save()
    except:
        pass


def user_login_failed(sender, credentials, **kwargs):
    """
    signal to catch failed logins and log them in the audit log
    """
    try:
        event = 'failed_login'
        user_model = get_user_model()
        d = {
            "event_time_gmt": get_time_gmt(),
            "event": event,
            "username": credentials[user_model.USERNAME_FIELD],
        }
        if AUDIT_TO_FILE:
            write_entry(d)
        login_event = AuditEvent(
            event=event,
            username=d['username'],
        )
        login_event.save()
    except:
        pass


models_signals.post_save.connect(
    post_save,
    dispatch_uid='easy_audit_signals_post_save'
)
models_signals.post_delete.connect(
    post_delete,
    dispatch_uid='easy_audit_signals_post_delete'
)
auth_signals.user_logged_in.connect(
    user_logged_in,
    dispatch_uid='audit_signals_logged_out'
)
auth_signals.user_logged_out.connect(
    user_logged_out,
    dispatch_uid='audit_signals_logged_out'
)
auth_signals.user_login_failed.connect(
    user_login_failed,
    dispatch_uid='audit_signals_login_failed'
)
