import base64
import smtplib
from django.core.mail.backends.smtp import EmailBackend
from oauth2client.client import AccessTokenCredentials

class OAuth2Backend(EmailBackend):
    def _send(self, email_message):
        if not email_message.recipients():
            return False
        self.open()
        credentials = AccessTokenCredentials(
            self._get_access_token(),
            'my-user-agent/1.0'
        )
        auth_string = 'user={}\1auth=Bearer {}\1\1'.format(
            email_message.from_email, credentials.access_token
        )
        auth_string = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
        self.connection.docmd('AUTH', 'XOAUTH2 ' + auth_string)
        try:
            self.connection.sendmail(email_message.from_email, email_message.recipients(), email_message.message().as_string())
        finally:
            self.close()
        return True

    def _get_access_token(self):
        # Retrieve access token from session or database
        credentials_json = self.session.get('credentials')
        credentials = AccessTokenCredentials.from_json(credentials_json)
        return credentials.access_token