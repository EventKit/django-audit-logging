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
from .utils import (get_audit_crud_dict, get_audit_login_dict, get_time_gmt, write_entry)

logger = logging.getLogger(__name__)
logger.info('Using audit_logging version: {}'.format(audit_logging_version.strip()))


def log_event(instance, event=None):
    if isinstance(instance, AuditEvent):
        return

    try:
        d = get_audit_crud_dict(instance, event)
        if d:
            if AUDIT_TO_FILE:
                write_entry(d)
            audit_event = AuditEvent(
                event=event
            )
            if d.get('user_details'):
                logger.debug('got user_details from instance to log: {}'.format(d.get('user_details')))
                if d.get('user_details').get('username'):
                    audit_event.username = d['user_details']['username']
                if d.get('user_details').get('email'):
                    audit_event.email = d['user_details']['email']
                if d.get('user_details').get('fullname'):
                    audit_event.fullname = d['user_details']['fullname']
                if d.get('user_details').get('superuser'):
                    audit_event.superuser = d['user_details']['superuser']
                if d.get('user_details').get('staff'):
                    audit_event.staff = d['user_details']['staff']
            if d.get('resource'):
                logger.debug('got resource details from instance to log: {}'.format(d.get('resource')))
                if d.get('resource').get('type'):
                    audit_event.resource_type = d['resource']['type']
                if d.get('resource').get('id'):
                    logger.debug('setting resource_uuid to {}'.format(d['resource']['id']))
                    audit_event.resource_uuid = d['resource']['id']
                if d.get('resource').get('title'):
                    audit_event.resource_title = d['resource']['title']
                if d.get('resource').get('username'):
                    audit_event.username = d['resource']['username']
            audit_event.save()
        else:
            logger.warn('get_audit_crud_dict() returned nothing')
    except Exception:
        logger.exception('Exception during audit event.')
        raise


def post_save(sender, instance, created, raw, using, update_fields, **kwargs):
    """
    signal to catch save signals (create and update) and log them in
    the audit log.
    """
    if isinstance(instance, AuditEvent):
        return
    logger.info('Received post_save signal for: {} ({})'.format(instance, type(instance)))

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
    logger.info('Received post_delete signal for: {} ({})'.format(instance, type(instance)))

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
