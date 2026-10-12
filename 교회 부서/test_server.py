import http.cookiejar
import json
from pathlib import Path
import secrets
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPCookieProcessor
from urllib.parse import quote

import server


class Client:
    def __init__(self, url):
        self.url, self.csrf = url, ''
        self.opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, path, data=None, **headers):
        request = Request(self.url + quote(path, safe='/?=&'), data=json.dumps(data).encode() if data is not None else None,
                          headers={'Content-Type': 'application/json', 'X-CSRF-Token': self.csrf, **headers})
        try:
            with self.opener.open(request) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)


class LockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'test.sqlite3')
        server.initialize(self.path)
        self.http = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        self.http.db_path, self.http.secure_cookies = self.path, False
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        url = f'http://127.0.0.1:{self.http.server_port}'
        self.clients = {}
        for username in ('owner', 'other', 'admin'):
            password = secrets.token_urlsafe(24)
            server.create_user(self.path, username, password, username == 'admin')
            client = Client(url)
            status, result = client.call('/api/login', {'username': username, 'password': password})
            self.assertEqual(status, 200)
            client.csrf = result['csrf']
            self.clients[username] = client
        self.guest = Client(url)
        self.event_id = self.create_event()['id']

    def create_event(self, department='예배부', day='2026-10-12', title='주일 예배'):
        status, result = self.clients['owner'].call('/api/event', {
            'action': 'create', 'department': department, 'day': day, 'title': title})
        self.assertEqual(status, 200)
        return result['event']

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join()
        self.temp.cleanup()

    def field(self, actor, action, version, **extra):
        return self.clients[actor].call('/api/field', {
            'department': '예배부', 'day': '2026-10-12', 'field': '인도자',
            'event_id': self.event_id, 'action': action, 'version': version, **extra})

    def lock(self):
        self.assertEqual(self.field('owner', 'save', 0, value='홍길동')[0], 200)
        self.assertEqual(self.field('owner', 'lock', 1)[0], 200)

    def test_first_writer_alone_can_lock(self):
        self.assertEqual(self.field('owner', 'save', 0, value='홍길동')[0], 200)
        self.assertEqual(self.field('other', 'lock', 1)[0], 403)
        self.assertEqual(self.field('admin', 'lock', 1)[0], 403)
        self.assertEqual(self.field('owner', 'lock', 1)[0], 200)

    def test_owner_can_unlock(self):
        self.lock()
        self.assertEqual(self.field('owner', 'unlock', 2)[0], 200)
        self.assertEqual(self.field('other', 'save', 3, value='수정')[0], 200)

    def test_admin_can_unlock(self):
        self.lock()
        self.assertEqual(self.field('admin', 'unlock', 2)[0], 200)

    def test_other_cannot_unlock_or_spoof_identity(self):
        self.lock()
        self.assertEqual(self.field('other', 'unlock', 2, admin=True, user_id=1, locked_by=2)[0], 403)

    def test_locked_value_rejects_every_writer(self):
        self.lock()
        for actor in self.clients:
            self.assertEqual(self.field(actor, 'save', 2, value='변조')[0], 403)

    def test_owner_does_not_change_after_edit_or_clear(self):
        self.field('owner', 'save', 0, value='최초')
        self.field('other', 'save', 1, value='')
        status, result = self.field('other', 'save', 2, value='다시 입력')
        self.assertEqual(status, 200)
        self.assertEqual(result['entry']['owner'], 'owner')
        self.assertEqual(self.field('other', 'lock', 3)[0], 403)

    def test_blank_does_not_claim_ownership(self):
        _, result = self.field('owner', 'save', 0, value='  ')
        self.assertIsNone(result['entry']['owner_id'])
        self.assertEqual(self.field('owner', 'lock', 1)[0], 403)
        _, result = self.field('other', 'save', 1, value='최초')
        self.assertEqual(result['entry']['owner'], 'other')

    def test_stale_update_cannot_overwrite_newer_lock(self):
        self.lock()
        self.assertEqual(self.field('other', 'save', 1, value='이전 버전')[0], 409)
        self.assertEqual(self.field('other', 'save', 0, value='최초 경쟁')[0], 409)

    def test_auth_csrf_logout(self):
        self.assertEqual(self.guest.call('/api/schedule?department=예배부&day=2026-10-12')[0], 401)
        client = self.clients['owner']
        token = client.csrf
        client.csrf = ''
        self.assertEqual(self.field('owner', 'save', 0, value='검증')[0], 403)
        client.csrf = token
        self.assertEqual(client.call('/api/logout', {})[0], 200)
        self.assertEqual(self.field('owner', 'save', 0, value='검증')[0], 401)

    def test_invalid_target_and_cross_origin(self):
        self.assertEqual(self.field('owner', 'save', 0, value='검증', day='2026-02-30')[0], 400)
        self.assertEqual(self.field('owner', 'save', 0, value='검증', field='없는 항목')[0], 400)
        self.assertEqual(self.clients['owner'].call('/api/logout', {}, Origin='https://evil.example')[0], 403)

    def test_independent_date_department_and_persistent_state(self):
        self.lock()
        next_day = self.create_event(day='2026-10-13')
        youth = self.create_event(department='청년부')
        self.assertEqual(self.field('other', 'save', 0, event_id=next_day['id'], day='2026-10-13', value='다음 날')[0], 200)
        self.assertEqual(self.field('other', 'save', 0, event_id=youth['id'], department='청년부', value='다른 부서')[0], 200)
        with server.connect(self.path) as db:
            entry = server.public_entry(db, self.event_id, '인도자')
            self.assertEqual(entry['locker'], 'owner')
            self.assertEqual(entry['value'], '홍길동')

    def test_multiple_events_keep_values_ownership_and_locks_separate(self):
        self.lock()
        second = self.create_event(title='저녁 예배')
        status, result = self.field('other', 'save', 0, event_id=second['id'], value='다른 담당자')
        self.assertEqual(status, 200)
        self.assertEqual(result['entry']['owner'], 'other')
        self.assertEqual(self.field('other', 'lock', 1, event_id=second['id'])[0], 200)
        with server.connect(self.path) as db:
            first = server.public_entry(db, self.event_id, '인도자')
            second_entry = server.public_entry(db, second['id'], '인도자')
            self.assertEqual(first['value'], '홍길동')
            self.assertEqual(first['locker'], 'owner')
            self.assertEqual(second_entry['value'], '다른 담당자')
            self.assertEqual(second_entry['locker'], 'other')

    def test_event_title_rename_persistence_and_conflict(self):
        self.lock()
        body = {'action': 'rename', 'event_id': self.event_id, 'department': '예배부',
                'day': '2026-10-12', 'title': '수정된 예배 제목', 'version': 0}
        status, result = self.clients['owner'].call('/api/event', body)
        self.assertEqual(status, 200)
        self.assertEqual(result['event']['title'], '수정된 예배 제목')
        self.assertEqual(result['entries'][0]['locker'], 'owner')
        self.assertEqual(self.clients['other'].call('/api/event', body)[0], 409)
        status, result = self.clients['owner'].call('/api/schedule?department=예배부&day=2026-10-12')
        self.assertEqual(status, 200)
        self.assertEqual(result['events'][0]['title'], '수정된 예배 제목')

    def test_date_view_does_not_create_an_event(self):
        status, result = self.clients['owner'].call('/api/schedule?department=예배부&day=2026-10-13')
        self.assertEqual(status, 200)
        self.assertEqual(result['events'], [])

    def test_event_validation_and_authentication(self):
        body = {'action': 'create', 'department': '예배부', 'day': '2026-10-12', 'title': '새 일정'}
        self.assertEqual(self.guest.call('/api/event', body)[0], 401)
        for title in ('', '  ', 'x' * 101):
            self.assertEqual(self.clients['owner'].call('/api/event', {**body, 'title': title})[0], 400)
        self.assertEqual(self.field('owner', 'save', 0, event_id='missing', value='입력')[0], 404)
        self.assertEqual(self.field('owner', 'save', 0, day='2026-10-13', value='입력')[0], 404)

    def test_legacy_migration_preserves_lock_and_runs_once(self):
        with server.connect(self.path) as db:
            owner_id = db.execute("SELECT id FROM users WHERE username='owner'").fetchone()['id']
            db.execute('INSERT INTO entries VALUES(?,?,?,?,?,?,?)',
                       ('방송부', '2026-10-15', '설교자', '기존 입력', owner_id, owner_id, 7))
            db.execute("DELETE FROM migrations WHERE name='multiple-events-v1'")
        server.initialize(self.path)
        server.initialize(self.path)
        with server.connect(self.path) as db:
            events = db.execute("SELECT * FROM events WHERE department='방송부' AND day='2026-10-15'").fetchall()
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]['title'], '기존 일정')
            entry = server.public_entry(db, events[0]['id'], '설교자')
            self.assertEqual(entry['value'], '기존 입력')
            self.assertEqual(entry['version'], 7)
            self.assertEqual(entry['owner'], 'owner')
            self.assertEqual(entry['locker'], 'owner')

    def test_temporary_open_edits_locked_values_without_erasing_permissions(self):
        self.lock()
        self.http.temporary_open = True
        self.http.open_csrf = secrets.token_urlsafe(32)
        status, session = self.guest.call('/api/session')
        self.assertEqual(status, 200)
        self.assertTrue(session['temporary_open'])
        self.guest.csrf = session['csrf']
        body = {'department': '예배부', 'day': '2026-10-12', 'event_id': self.event_id,
                'field': '인도자', 'action': 'save', 'version': 2, 'value': '임시 수정'}
        status, result = self.guest.call('/api/field', body)
        self.assertEqual(status, 200)
        self.assertEqual(result['entry']['value'], '임시 수정')
        self.assertEqual(result['entry']['owner'], 'owner')
        self.assertEqual(result['entry']['locker'], 'owner')
        self.assertEqual(self.guest.call('/api/field', {**body, 'action': 'unlock', 'version': 3})[0], 409)
        self.http.temporary_open = False
        self.assertEqual(self.guest.call('/api/field', {**body, 'version': 3})[0], 401)
        self.assertEqual(self.field('other', 'save', 3, value='수정 시도')[0], 403)
        self.assertEqual(self.field('admin', 'unlock', 3)[0], 200)

    def test_temporary_open_creates_events_without_claiming_field_ownership(self):
        self.http.temporary_open = True
        self.http.open_csrf = secrets.token_urlsafe(32)
        self.guest.csrf = self.guest.call('/api/session')[1]['csrf']
        status, event = self.guest.call('/api/event', {'action': 'create', 'department': '예배부',
                                                       'day': '2026-10-12', 'title': '임시 일정'})
        self.assertEqual(status, 200)
        body = {'department': '예배부', 'day': '2026-10-12', 'event_id': event['event']['id'],
                'field': '인도자', 'action': 'save', 'version': 0, 'value': '임시 입력'}
        status, result = self.guest.call('/api/field', body)
        self.assertEqual(status, 200)
        self.assertIsNone(result['entry']['owner_id'])
        self.http.temporary_open = False
        status, result = self.clients['owner'].call('/api/field', {**body, 'version': 1})
        self.assertEqual(status, 200)
        self.assertEqual(result['entry']['owner'], 'owner')


    def test_signup_is_normal_and_cannot_claim_reserved_admin(self):
        password = secrets.token_urlsafe(24)
        body = {'username': 'new-member', 'password': password, 'password_confirm': password, 'admin': True}
        self.assertEqual(self.guest.call('/api/register', body)[0], 201)
        status, result = self.guest.call('/api/login', body)
        self.assertEqual(status, 200)
        self.assertFalse(result['user']['admin'])
        self.assertEqual(self.guest.call('/api/register', body)[0], 409)
        with server.connect(self.path) as db:
            db.execute('INSERT INTO users(username,salt,password_hash,admin) VALUES(?,?,?,1)',
                       ('reserved-admin', secrets.token_hex(16), ''))
        self.assertEqual(self.guest.call('/api/register', {**body, 'username': 'reserved-admin'})[0], 409)
        with server.connect(self.path) as db:
            row = db.execute("SELECT * FROM users WHERE username='reserved-admin'").fetchone()
            self.assertEqual(row['password_hash'], '')
            self.assertEqual(row['admin'], 1)
            row = db.execute("SELECT * FROM users WHERE username='new-member'").fetchone()
            self.assertNotEqual(row['password_hash'], password)

    def test_admin_suspension_masks_existing_sessions_and_preserves_saved_roles(self):
        self.lock()
        self.http.admin_suspended = True
        self.http.temporary_open = True
        self.http.open_csrf = secrets.token_urlsafe(32)
        status, session = self.clients['admin'].call('/api/session')
        self.assertEqual(status, 200)
        self.assertTrue(session['admin_suspended'])
        self.assertFalse(session['user']['admin'])
        self.assertEqual(self.field('admin', 'unlock', 2)[0], 409)
        password = secrets.token_urlsafe(24)
        server.create_user(self.path, 'another-admin', password, admin=True)
        status, login = self.guest.call('/api/login', {'username': 'another-admin', 'password': password})
        self.assertEqual(status, 200)
        self.assertFalse(login['user']['admin'])
        with server.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT admin FROM users WHERE username='admin'").fetchone()['admin'], 1)
            self.assertEqual(server.public_entry(db, self.event_id, '인도자')['locker'], 'owner')
        self.http.admin_suspended = self.http.temporary_open = False
        self.assertTrue(self.clients['admin'].call('/api/session')[1]['user']['admin'])
        self.assertEqual(self.field('admin', 'unlock', 2)[0], 200)

    def test_login_disabled_keeps_all_schedule_functions_available_anonymously(self):
        self.http.login_disabled = self.http.temporary_open = self.http.admin_suspended = True
        self.http.open_csrf = secrets.token_urlsafe(32)
        _, session = self.clients['admin'].call('/api/session')
        self.assertTrue(session['login_disabled'])
        self.assertIsNone(session['user']['id'])
        self.guest.csrf = session['csrf']
        for endpoint in ('/api/login', '/api/register', '/api/logout'):
            self.assertEqual(self.guest.call(endpoint, {})[0], 409)
        for department, fields in server.FIELDS.items():
            status, result = self.guest.call('/api/event', {'action': 'create', 'department': department,
                                                           'day': '2026-10-12', 'title': '로그인 없는 일정'})
            self.assertEqual(status, 200)
            self.assertEqual([row['field'] for row in result['entries']], fields)
            event = result['event']
            status, result = self.guest.call('/api/event', {'action': 'rename', 'department': department,
                'day': event['day'], 'event_id': event['id'], 'version': 0, 'title': '제목 수정'})
            self.assertEqual(status, 200)
            self.assertEqual(result['event']['title'], '제목 수정')
            status, result = self.guest.call('/api/field', {'action': 'save', 'department': department,
                'day': event['day'], 'event_id': event['id'], 'version': 0, 'field': fields[0], 'value': '담당자'})
            self.assertEqual(status, 200)
            self.assertEqual(result['entry']['value'], '담당자')

    def test_signup_validation_confirmation_and_origin(self):
        password = secrets.token_urlsafe(24)
        body = {'username': 'new-member', 'password': password, 'password_confirm': password}
        self.assertEqual(self.guest.call('/api/register', {**body, 'password_confirm': 'different'})[0], 400)
        self.assertEqual(self.guest.call('/api/register', {**body, 'username': '  '})[0], 400)
        self.assertEqual(self.guest.call('/api/register', {**body, 'password': 'tiny', 'password_confirm': 'tiny'})[0], 400)
        self.assertEqual(self.guest.call('/api/register', body, Origin='https://evil.example')[0], 403)

    def test_optional_login_and_signup_in_temporary_mode(self):
        self.http.temporary_open = True
        self.http.open_csrf = secrets.token_urlsafe(32)
        short = secrets.token_hex(2)
        body = {'username': 'temporary-member', 'password': short, 'password_confirm': short}
        self.assertEqual(self.guest.call('/api/register', body)[0], 201)
        status, session = self.guest.call('/api/login', body)
        self.assertEqual(status, 200)
        self.assertEqual(session['user']['username'], 'temporary-member')
        self.guest.csrf = session['csrf']
        _, current = self.guest.call('/api/session')
        self.assertTrue(current['temporary_open'])
        self.assertEqual(current['user']['id'], session['user']['id'])
        self.assertEqual(self.guest.call('/api/logout', {})[0], 200)
        _, current = self.guest.call('/api/session')
        self.assertIsNone(current['user']['id'])
        self.assertTrue(current['temporary_open'])


if __name__ == '__main__':
    unittest.main()
