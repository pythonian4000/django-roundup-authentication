import binascii, MySQLdb, random, re, string, time

import roundup.cgi
from roundup.cgi.client import LiberalCookie
from roundup.cgi.actions import LoginAction, LogoutAction
from roundup.password import Password

allowed_usernames = [
        'sufjan'
        ]

class SessionDjango:
    """
    Needs DB to be already opened by client

    Session attributes at instantiation:

    - "client" - reference to client for add_cookie function
    - "session_db" - session DB manager
    - "cookie_name" - name of the cookie with session id
    - "_sid" - session id for current user
    - "_data" - session data cache

    session = Session(client)
    session.set(name=value)
    value = session.get(name)

    session.destroy()  # delete current session
    session.clean_up() # clean up session table

    session.update(set_cookie=True, expire=3600*24*365)
                       # refresh session expiration time, setting persistent
                       # cookie if needed to last for 'expire' seconds

    """

    def __init__(self, client):
        self._data = {}
        self._sid  = None

        self.client = client
        self.session_db = client.db.getSessionManager()
        self.d_db = MySQLdb.connect(
                "localhost", # Django database host
                "roundupuser", # MySQL user with limited Django permissions
                "secret", # MySQL user password
                "oh_milestone_a") # Django database
        self.d_auth_user_table = 'auth_user'
        self.d_sessionprofile_table = 'sessionprofile_sessionprofile'
        self.d_session_table = 'django_session'

        # parse cookies for session id
        self.d_cookie_name = 'sessionid'
        self.cookie_name = 'roundup_session_%s' % \
            re.sub('[^a-zA-Z]', '', client.instance.config.TRACKER_NAME)
        cookies = LiberalCookie(client.env.get('HTTP_COOKIE', ''))
        self.d_cookie_value = ''
        # Check if we are logged into Django
        if self.d_cookie_name in cookies:
            self.d_cookie_value = cookies[self.d_cookie_name].value
            d_cursor = self.d_db.cursor()
            params = {
                    'au': self.d_auth_user_table,
                    'sp': self.d_sessionprofile_table,
                    'dsid': self.d_cookie_value
                    }
            sql = """SELECT %(au)s.id as d_user_id, username, email FROM %(au)s, %(sp)s
                    WHERE %(au)s.id=user_id AND session_id='%(dsid)s'""" % params
            try:
                d_cursor.execute(sql)
            except Exception as e:
                # Something went wrong, so abort
                self._ensure_logged_out()
                return
            row = d_cursor.fetchone()
            if row:
                # There is a Django session present
                user_id = '%s' % row[0]
                # Fetch corresponding Roundup user ID
                r_uid = self.client.db.user.stringFind(django_id=user_id)
                local_id = r_uid[0] if r_uid else 0
                if not r_uid:
                    # Django user does not exist in the Roundup database.
                    username = row[1]
                    # Check if Roundup User with this username exists.
                    try:
                        # If this works, User exists.
                        local_id = self.client.db.user.lookup(username)
                    except KeyError:
                        # User doesn't exist, so create them.
                        email = row[2]
                        local_id = self.client.db.user.create(
                                username = username,
                                password = self._gen_password(),
                                address  = email,
                                roles    = self.client.db.config['NEW_WEB_USER_ROLES'])
                    # Add Django ID to Roundup User.
                    self.client.db.user.set(local_id, django_id=user_id)

                    self.client.db.commit()

                # Now that we have the local ID, set session user.
                # Don't use username from above in case the Roundup
                # username has been changed.
                local_user = self.client.db.user.get(local_id, 'username')
                self.set(user=local_user)

                # Do normal Roundup cookie checks.
                if self.cookie_name in cookies:
                    if not self.session_db.exists(cookies[self.cookie_name].value):
                        self._sid = None
                        # remove old cookie
                        self.client.add_cookie(self.cookie_name, None)
                    else:
                        self._sid = cookies[self.cookie_name].value
                        self._data = self.session_db.getall(self._sid)
            else:
                # We are not logged into Django so make sure we aren't logged in here.
                self._ensure_logged_out()
        else:
            # Certain users who cannot log into Django (such as bots) will be allowed
            # to log in anyway via username and password. So do Roundup cookie checks
            # here to see if they are one of those users.
            if self.cookie_name in cookies:
                if not self.session_db.exists(cookies[self.cookie_name].value):
                    self._sid = None
                    # remove old cookie
                    self.client.add_cookie(self.cookie_name, None)
                else:
                    self._sid = cookies[self.cookie_name].value
                    self._data = self.session_db.getall(self._sid)
                username = self.get('user')
                if username not in allowed_usernames:
                    # We are not logged into Django and not allowed here via username login.
                    # So make sure we aren't logged in here.
                    self._ensure_logged_out()
            else:
                # We are not logged into Django and not allowed here via username login.
                # So make sure we aren't logged in here.
                self._ensure_logged_out()

    def _ensure_logged_out(self):
        self.client.make_user_anonymous()
        self.destroy()
        self.client.classname = None
        self.client.nodeid = None
        self.client.template = None

    def _gen_password(self, length=12, chars=string.letters + string.digits):
        return Password(''.join([random.choice(chars) for i in range(length)]))

    def _gen_sid(self):
        """ generate a unique session key """
        while 1:
            s = '%s%s'%(time.time(), random.random())
            s = binascii.b2a_base64(s).strip()
            if not self.session_db.exists(s):
                break

        # clean up the base64
        if s[-1] == '=':
            if s[-2] == '=':
                s = s[:-2]
            else:
                s = s[:-1]
        return s

    def clean_up(self):
        """Remove expired sessions"""
        self.session_db.clean()

    def destroy(self):
        self.client.add_cookie(self.cookie_name, None)
        self._data = {}
        if self._sid:
            self.session_db.destroy(self._sid)
        self.client.db.commit()

    def get(self, name, default=None):
        return self._data.get(name, default)

    def set(self, **kwargs):
        self._data.update(kwargs)
        if not self._sid:
            self._sid = self._gen_sid()
            self.session_db.set(self._sid, **self._data)
            # add session cookie
            self.update(set_cookie=True)

            # XXX added when patching 1.4.4 for backward compatibility
            # XXX remove
            self.client.session = self._sid
        else:
            self.session_db.set(self._sid, **self._data)
            self.client.db.commit()

    def update(self, set_cookie=False, expire=None):
        """ update timestamp in db to avoid expiration

            if 'set_cookie' is True, set cookie with 'expire' seconds lifetime
            if 'expire' is None - session will be closed with the browser
             
            XXX the session can be purged within a week even if a cookie
                lifetime is longer
        """
        self.session_db.updateTimestamp(self._sid)
        self.client.db.commit()

        if set_cookie:
            self.client.add_cookie(self.cookie_name, self._sid, expire=expire)

class LoginDjango(LoginAction):
    def handle(self):
        # We only want certain users to be able to log in with a username and password.
        # So we check for those users here.
        if self.client.env['REQUEST_METHOD'] == 'POST':
            if '__login_name' in self.form:
                username = self.form['__login_name'].value
                if username in allowed_usernames:
                    # User is allowed to login, so continue with action as normal.
                    LoginAction.handle(self)
                    return
        # Redirect to the Django login page, which will login and redirect back here.
        login_url = "https://openhatch.org/account/login/?next=/bugs/"
        self.client.setHeader("Location", login_url)

class LogoutDjango(LogoutAction):
    def handle(self):
        # Delete Django session from its tables.
        cookies = LiberalCookie(self.client.env.get('HTTP_COOKIE', ''))
        cookie_value = cookies['sessionid'].value
        d_cursor = self.client.session_api.d_db.cursor()
        sql1 = """DELETE FROM %s WHERE session_key='%s'""" % \
                (self.client.session_api.d_session_table, cookie_value)
        try:
            d_cursor.execute(sql1)
        except:
            pass
        sql2 = """DELETE FROM %s WHERE session_id='%s'""" % \
                (self.client.session_api.d_sessionprofile_table, cookie_value)
        try:
            d_cursor.execute(sql2)
        except:
            pass

        # Now continue with Roundup's normal logout procedures.
        LogoutAction.handle(self)

roundup.cgi.client.Session = SessionDjango

def init(instance):
    instance.registerAction('login', LoginDjango)
    instance.registerAction('logout', LogoutDjango)
