""" Provides alterntive open() & File objects which log create/read/update/delete.
"""
import os
from audit_logging.models import AuditEvent
import logging
from django.db import connection
from django.conf import settings
from audit_logging.utils import log_event


logger = logging.getLogger(__name__)


def logging_open(filepath, mode='r', user_details=None):
    """ Equivalent of builtin open() which logs file creation to AuditEvent if appropriate and returns a LoggingFile
        instead of regular file-like object.
    """
    exists_before = os.path.exists(filepath)
    res = open(filepath, mode)

    if getattr(settings, 'AUDIT_FILE_EVENTS', True):
        res = LoggingFile(res, user_details)
        exists_after = os.path.exists(filepath)

        if not exists_before and exists_after:
            # This is just to make it easier to trace when user_details haven't been sent
            if user_details is None:
                user_details = {'username': 'unknown-logging_open'}
            log_event(event='FileCreate', resource_type='file', resource_uuid=filepath, user_details=user_details)

    return res


class LoggingFile(object):
    """ Wraps a regular file-like object so that reads/writes are logged to AuditEvent.
    """
    AuditEvent = None

    def __init__(self, regular_file, user_details):
        """ regular_file should be an open file-like object
        """
        # Import AuditEvent here so this module can be imported before django apps are ready
        from audit_logging.models import AuditEvent
        self.AuditEvent = AuditEvent
        self.regular_file = regular_file
        self.user_details = user_details
        self.writes = 0
        self.reads = 0

    def write(self, *args, **kwargs):
        res = self.regular_file.write(*args, **kwargs)
        self.writes += 1
        return res

    def writelines(self, *args, **kwargs):
        res = self.regular_file.writelines(*args, **kwargs)
        self.writes += 1
        return res

    def truncate(self, *args, **kwargs):
        res = self.regular_file.truncate(*args, **kwargs)
        self.writes += 1
        return res

    def read(self, *args, **kwargs):
        res = self.regular_file.read(*args, **kwargs)
        self.reads += 1
        return res

    def readline(self, *args, **kwargs):
        res = self.regular_file.readline(*args, **kwargs)
        self.reads += 1
        return res

    def readlines(self, *args, **kwargs):
        res = self.regular_file.readlines(*args, **kwargs)
        self.reads += 1
        return res

    def __enter__(self, *args, **kwargs):
        log_event(
            event='FileOpen', resource_type='file', resource_uuid=self.regular_file.name,
            user_details=self.user_details
        )
        return self

    def __exit__(self, *args, **kwargs):
        event = "File{0}{1}Close".format('Read' if self.reads else '', 'Write' if self.writes else '')
        log_event(
            event=event, resource_type='file', resource_uuid=self.regular_file.name,
            user_details=self.user_details
        )
        self.regular_file.close()

    def __iter__(self, *args, **kwargs):
        return self.regular_file.__iter__(*args, **kwargs)

    def __next__(self, *args, **kwargs):
        return self.regular_file.__next__(*args, **kwargs)

    def __getattr__(self, attr):
        if hasattr(self.regular_file, attr):
            res = getattr(self.regular_file, attr)
        else:
            raise AttributeError("LoggingFile object has no attribute '{}'".format(attr))

        return res
