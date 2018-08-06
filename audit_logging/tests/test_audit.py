# Perform audit_logging_tests for auditing.
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse
from audit_logging.models import AuditEvent


class LoggedInTestCase(TestCase):

    def logout(self):
        self.client.logout()

    def login(self, admin_user=False):
        if(admin_user):
            username, password = self.create_admin_user()
        else:
            username, password = self.create_test_user()

        logged_in = self.client.login(
            username=username,
            password=password
        )
        self.assertTrue(logged_in)
        return(username, password)

    def create_test_user(self):
        User = get_user_model()

        test_users = User.objects.filter(
            username='test'
        )
        if test_users.count() > 0:
            self.test_user = test_users[0]
        else:
            self.test_user = User.objects.create_user(
                username='test',
                email=''
            )
        self.test_user.set_password('test')
        self.test_user.save()

        return ('test', 'test')

    def create_admin_user(self):
        # Admin user is the overlord for the system (django superuser).
        User = get_user_model()

        admin_users = User.objects.filter(
            is_superuser=True
        )
        if admin_users.count() > 0:
            self.admin_user = admin_users[0]
        else:
            self.admin_user = User.objects.create_user(
                username='admin',
                email='',
                is_superuser=True,
            )
        self.admin_user.set_password('admin')
        self.admin_user.save()

        return ('admin', 'admin')


class AuditTest(LoggedInTestCase):

    def test(self):
        self.login()

        last_event = AuditEvent.objects.latest('datetime')
        self.assertEqual(last_event.event, 'login')
        self.client.logout()
        last_event = AuditEvent.objects.latest('datetime')
        self.assertEqual(last_event.event, 'logout')
        self.client.login(
            username='bogus',
            password='bogus'
        )
        last_event = AuditEvent.objects.latest('datetime')
        self.assertEqual(last_event.event, 'failed_login')


class AuditAdminTest(LoggedInTestCase):

    def test_model_admin(self):
        self.login(admin_user=True)

        url = reverse("admin:audit_logging_auditevent_changelist")
        r = self.client.get(url, follow=True)

        msg = 'Did not get admin audit event list (status: {}):\n{}'.format(r.status_code, r.content)
        self.assertEqual(r.status_code, 200, msg)
