"""Authenticated department schedules. Python standard library only."""
import argparse
from datetime import date
import getpass
import hashlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import parse_qs, urlsplit

FIELDS = {
    '예배부': ['인도자', '메인', '드럼', '베이스', '세컨', '일렉', '싱어1', '싱어2', '싱어3', '싱어4'],
    '방송부': ['설교자', '사회자', '특송자', '음향', '영상', '자막', '조명', 'PD'],
    '아동부': ['설교자', '기도자', '찬양인도자', '건반', '드럼', '교사1', '교사2', '교사3', '교사4', '교사5', '교사6'],
    '청소년부': ['설교자', '인도자', '메인', '드럼', '베이스', '세컨', '일렉', '싱어1', '싱어2', '싱어3', '싱어4', '교사1', '교사2', '교사3', '교사4', '교사5', '교사6'],
    '청년부': ['인도자', '메인', '드럼', '베이스', '세컨', '일렉', '싱어1', '싱어2', '싱어3', '싱어4', '싱어5', '싱어6'],
}


def connect(path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    return db


def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
          salt TEXT NOT NULL, password_hash TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
          csrf TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS entries (
          department TEXT NOT NULL, day TEXT NOT NULL, field TEXT NOT NULL,
          value TEXT NOT NULL DEFAULT '', owner_id INTEGER REFERENCES users(id),
          locked_by INTEGER REFERENCES users(id), version INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (department, day, field));
        CREATE TABLE IF NOT EXISTS login_attempts (
          username TEXT PRIMARY KEY, count INTEGER NOT NULL, since REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY, department TEXT NOT NULL, day TEXT NOT NULL,
          title TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0,
          created_by INTEGER REFERENCES users(id));
        CREATE INDEX IF NOT EXISTS events_by_day ON events(department, day);
        CREATE TABLE IF NOT EXISTS event_entries (
          event_id TEXT NOT NULL REFERENCES events(id), field TEXT NOT NULL,
          value TEXT NOT NULL DEFAULT '', owner_id INTEGER REFERENCES users(id),
          locked_by INTEGER REFERENCES users(id), version INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (event_id, field));
        CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS signup_attempts (
          address TEXT PRIMARY KEY, count INTEGER NOT NULL, since REAL NOT NULL);
        ''')
        db.execute('BEGIN IMMEDIATE')
        if not db.execute("SELECT 1 FROM migrations WHERE name='multiple-events-v1'").fetchone():
            for row in db.execute('SELECT DISTINCT department, day FROM entries').fetchall():
                event_id = secrets.token_hex(16)
                db.execute('INSERT INTO events(id,department,day,title) VALUES(?,?,?,?)',
                           (event_id, row['department'], row['day'], '기존 일정'))
                db.execute('''INSERT INTO event_entries SELECT ?,field,value,owner_id,locked_by,version
                    FROM entries WHERE department=? AND day=?''', (event_id, row['department'], row['day']))
            db.execute("INSERT INTO migrations VALUES('multiple-events-v1')")


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def create_user(path, username, password, admin=False, temporary_password=False):
    if not isinstance(username, str) or not username.strip() or len(username) > 60:
        raise ValueError('아이디는 1~60자여야 합니다.')
    minimum = 4 if temporary_password else 12
    if len(password) < minimum or len(password) > 256:
        raise ValueError(f'비밀번호는 {minimum}~256자여야 합니다.')
    salt = secrets.token_hex(16)
    with connect(path) as db:
        reserved = db.execute('SELECT password_hash FROM users WHERE username=?', (username.strip(),)).fetchone()
        if reserved and reserved['password_hash'] == '':
            db.execute('UPDATE users SET salt=?,password_hash=? WHERE username=?',
                       (salt, password_hash(password, salt), username.strip()))
            return
        db.execute('INSERT INTO users(username,salt,password_hash,admin) VALUES(?,?,?,?)',
                   (username.strip(), salt, password_hash(password, salt), int(admin)))


def public_user(user, admin_suspended=False):
    return {'id': user['id'], 'username': user['username'], 'admin': bool(user['admin']) and not admin_suspended}


def public_entry(db, event_id, field):
    row = db.execute('''SELECT e.*, o.username AS owner, l.username AS locker
      FROM event_entries e LEFT JOIN users o ON o.id=e.owner_id
      LEFT JOIN users l ON l.id=e.locked_by WHERE event_id=? AND field=?''',
                     (event_id, field)).fetchone()
    if not row:
        return {'field': field, 'value': '', 'owner_id': None, 'owner': None,
                'locked_by': None, 'locker': None, 'version': 0}
    return {key: row[key] for key in ('field', 'value', 'owner_id', 'owner', 'locked_by', 'locker', 'version')}


def event_payload(db, event):
    return {'event': dict(event), 'entries': [public_entry(db, event['id'], field) for field in FIELDS[event['department']]]}


class ApiError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, data, cookie=None):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def cookie(self, token, age):
        return f'department_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}' + ('; Secure' if self.server.secure_cookies else '')

    def session(self, db):
        guest = ({'id': None, 'username': '임시 편집', 'admin': False,
                  'csrf': self.server.open_csrf, 'token_hash': ''}
                 if getattr(self.server, 'temporary_open', False) else None)
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get('Cookie', ''))
            token = cookies['department_session'].value
        except (KeyError, ValueError):
            return guest
        user = db.execute('''SELECT u.*, s.csrf, s.token_hash FROM sessions s
            JOIN users u ON u.id=s.user_id WHERE token_hash=? AND expires>?''',
            (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone() or guest
        if user and getattr(self.server, 'admin_suspended', False):
            user = dict(user)
            user['admin'] = 0
        return user

    def target(self, body):
        department, day = body.get('department'), body.get('day')
        if not isinstance(department, str) or department not in FIELDS or not isinstance(day, str):
            raise ApiError(400, '부서와 날짜를 확인하세요.')
        try:
            if date.fromisoformat(day).isoformat() != day:
                raise ValueError()
        except ValueError:
            raise ApiError(400, '날짜를 확인하세요.')
        return department, day

    def event_target(self, db, body):
        department, day = self.target(body)
        event_id = body.get('event_id')
        if not isinstance(event_id, str):
            raise ApiError(400, '일정을 선택하세요.')
        event = db.execute('SELECT * FROM events WHERE id=? AND department=? AND day=?',
                           (event_id, department, day)).fetchone()
        if not event:
            raise ApiError(404, '해당 날짜와 부서에 일정이 없습니다.')
        return event

    def event_title(self, body):
        title = body.get('title')
        if not isinstance(title, str) or not title.strip() or len(title) > 100:
            raise ApiError(400, '일정 제목은 1~100자로 입력하세요.')
        return title.strip()

    def do_GET(self):
        path = urlsplit(self.path)
        if path.path in ('/', '/department-app/', '/department-app/index.html', '/index.html'):
            body = Path(__file__).with_name('index.html').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            with connect(self.server.db_path) as db:
                user = self.session(db)
                if path.path == '/api/session':
                    self.reply(200, {'user': public_user(user) if user else None,
                                     'csrf': user['csrf'] if user else None,
                                     'temporary_open': getattr(self.server, 'temporary_open', False),
                                     'admin_suspended': getattr(self.server, 'admin_suspended', False)})
                    return
                if not user:
                    raise ApiError(401, '로그인이 필요합니다.')
                if path.path not in ('/api/schedule', '/api/event'):
                    raise ApiError(404, '요청한 페이지가 없습니다.')
                params = {k: v[0] for k, v in parse_qs(path.query).items()}
                department, day = self.target(params)
                if path.path == '/api/event':
                    self.reply(200, event_payload(db, self.event_target(db, params)))
                else:
                    rows = db.execute('SELECT * FROM events WHERE department=? AND day=? ORDER BY rowid',
                                      (department, day)).fetchall()
                    self.reply(200, {'events': [dict(row) for row in rows]})
        except ApiError as error:
            self.reply(error.status, {'error': error.message})

    def do_POST(self):
        try:
            # Cross-origin requests are refused, including login CSRF.
            if self.headers.get('Sec-Fetch-Site') == 'cross-site':
                raise ApiError(403, '다른 사이트의 요청은 허용되지 않습니다.')
            origin = self.headers.get('Origin')
            if origin and urlsplit(origin).netloc != self.headers.get('Host'):
                raise ApiError(403, '다른 사이트의 요청은 허용되지 않습니다.')
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                raise ApiError(415, '올바른 요청 형식이 필요합니다.')
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 16384:
                    raise ValueError()
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError()
            except (ValueError, UnicodeDecodeError):
                raise ApiError(400, '잘못된 요청입니다.')
            with connect(self.server.db_path) as db:
                db.execute('BEGIN IMMEDIATE')
                temporary_open = getattr(self.server, 'temporary_open', False)
                if self.path == '/api/register':
                    username, password = body.get('username'), body.get('password')
                    minimum = 4 if temporary_open else 12
                    if not isinstance(username, str) or not username.strip() or len(username) > 60:
                        raise ApiError(400, '아이디는 1~60자로 입력하세요.')
                    if not isinstance(password, str) or not minimum <= len(password) <= 256:
                        raise ApiError(400, f'비밀번호는 {minimum}~256자로 입력하세요.')
                    if body.get('password_confirm') != password:
                        raise ApiError(400, '비밀번호 확인이 일치하지 않습니다.')
                    username = username.strip()
                    # Existing and reserved administrator accounts can never be claimed via signup.
                    if db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                        raise ApiError(409, '이미 사용 중인 아이디입니다. 다른 아이디를 입력하세요.')
                    address = self.client_address[0]
                    attempt = db.execute('SELECT * FROM signup_attempts WHERE address=?', (address,)).fetchone()
                    recent = attempt and attempt['since'] > time.time() - 3600
                    if recent and attempt['count'] >= 10:
                        raise ApiError(429, '회원가입 시도가 많습니다. 잠시 후 다시 시도하세요.')
                    salt = secrets.token_hex(16)
                    db.execute('INSERT INTO users(username,salt,password_hash,admin) VALUES(?,?,?,0)',
                               (username, salt, password_hash(password, salt)))
                    db.execute('INSERT OR REPLACE INTO signup_attempts VALUES(?,?,?)',
                               (address, attempt['count'] + 1 if recent else 1, attempt['since'] if recent else time.time()))
                    db.commit()
                    self.reply(201, {'message': '회원가입이 완료되었습니다. 로그인해 주세요.'})
                    return
                if self.path == '/api/login':
                    username, password = body.get('username'), body.get('password')
                    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 60 or len(password) > 256:
                        raise ApiError(400, '아이디와 비밀번호를 확인하세요.')
                    username = username.strip()
                    attempt = db.execute('SELECT * FROM login_attempts WHERE username=?', (username,)).fetchone()
                    if attempt and attempt['since'] > time.time() - 300 and attempt['count'] >= 5:
                        raise ApiError(429, '로그인 시도가 많습니다. 5분 후 다시 시도하세요.')
                    user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
                    digest = password_hash(password, user['salt'] if user else '00' * 16)
                    if not user or not secrets.compare_digest(digest, user['password_hash']):
                        count = attempt['count'] + 1 if attempt and attempt['since'] > time.time() - 300 else 1
                        since = attempt['since'] if count > 1 else time.time()
                        db.execute('INSERT OR REPLACE INTO login_attempts VALUES(?,?,?)', (username, count, since))
                        db.commit()
                        raise ApiError(401, '아이디 또는 비밀번호가 올바르지 않습니다.')
                    db.execute('DELETE FROM login_attempts WHERE username=?', (username,))
                    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                    db.execute('DELETE FROM sessions WHERE expires<=?', (time.time(),))
                    old_session = self.session(db)
                    if old_session:
                        db.execute('DELETE FROM sessions WHERE token_hash=?', (old_session['token_hash'],))
                    db.execute('INSERT INTO sessions VALUES(?,?,?,?)',
                               (hashlib.sha256(token.encode()).hexdigest(), user['id'], csrf, time.time() + 43200))
                    db.commit()
                    self.reply(200, {'user': public_user(user, getattr(self.server, 'admin_suspended', False)), 'csrf': csrf}, self.cookie(token, 43200))
                    return
                user = self.session(db)
                if not user:
                    raise ApiError(401, '로그인이 필요합니다.')
                if not secrets.compare_digest(self.headers.get('X-CSRF-Token', ''), user['csrf']):
                    raise ApiError(403, '인증 정보를 새로 확인하세요.')
                if self.path == '/api/logout':
                    db.execute('DELETE FROM sessions WHERE token_hash=?', (user['token_hash'],))
                    db.commit()
                    self.reply(200, {'ok': True}, self.cookie('', 0))
                    return
                if self.path == '/api/event':
                    action = body.get('action')
                    title = self.event_title(body)
                    if action == 'create':
                        department, day = self.target(body)
                        event_id = secrets.token_hex(16)
                        db.execute('INSERT INTO events VALUES(?,?,?,?,0,?)',
                                   (event_id, department, day, title, user['id']))
                        event = db.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
                    elif action == 'rename':
                        event = self.event_target(db, body)
                        if type(body.get('version')) is not int or body['version'] != event['version']:
                            raise ApiError(409, '일정 제목이 변경되었습니다. 최신 내용을 불러오세요.')
                        db.execute('UPDATE events SET title=?,version=version+1 WHERE id=?', (title, event['id']))
                        event = db.execute('SELECT * FROM events WHERE id=?', (event['id'],)).fetchone()
                    else:
                        raise ApiError(400, '일정 동작을 확인하세요.')
                    result = event_payload(db, event)
                    db.commit()
                    self.reply(200, result)
                    return
                if self.path != '/api/field':
                    raise ApiError(404, '요청한 기능이 없습니다.')
                department, day = self.target(body)
                event = self.event_target(db, body)
                field, action = body.get('field'), body.get('action')
                if field not in FIELDS[department] or action not in ('save', 'lock', 'unlock'):
                    raise ApiError(400, '항목과 동작을 확인하세요.')
                entry = public_entry(db, event['id'], field)
                version = body.get('version')
                if type(version) is not int or version != entry['version']:
                    raise ApiError(409, '다른 사용자가 변경했습니다. 새로 불러온 후 다시 시도하세요.')
                value, owner, locker = entry['value'], entry['owner_id'], entry['locked_by']
                if temporary_open and action != 'save':
                    raise ApiError(409, '임시 편집 모드에서는 잠금 기능을 사용하지 않습니다.')
                if action == 'save':
                    if locker is not None and not temporary_open:
                        raise ApiError(403, '잠긴 항목입니다. 먼저 잠금을 해제하세요.')
                    value = body.get('value')
                    if not isinstance(value, str) or len(value) > 500:
                        raise ApiError(400, '입력은 500자 이내여야 합니다.')
                    if owner is None and value.strip() and not temporary_open:
                        owner = user['id']
                elif action == 'lock':
                    if locker is not None or owner != user['id'] or not value.strip():
                        raise ApiError(403, '내용을 최초로 입력한 사람만 잠글 수 있습니다.')
                    locker = user['id']
                else:
                    if locker is None or (not user['admin'] and locker != user['id']):
                        raise ApiError(403, '관리자 또는 이 잠금을 건 사람만 해제할 수 있습니다.')
                    locker = None
                db.execute('''INSERT INTO event_entries VALUES(?,?,?,?,?,?)
                  ON CONFLICT(event_id,field) DO UPDATE SET
                  value=excluded.value,owner_id=excluded.owner_id,locked_by=excluded.locked_by,version=excluded.version''',
                           (event['id'], field, value, owner, locker, version + 1))
                result = public_entry(db, event['id'], field)
                db.commit()
                self.reply(200, {'entry': result})
        except ApiError as error:
            self.reply(error.status, {'error': error.message})
        except sqlite3.Error:
            self.reply(503, {'error': '저장소를 사용할 수 없습니다. 잠시 후 다시 시도하세요.'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='/workspace/church-system-data/schedules.sqlite3')
    parser.add_argument('--port', type=int, default=8001)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--secure-cookies', action='store_true')
    parser.add_argument('--create-user')
    parser.add_argument('--reserve-admin', action='append', default=[])
    parser.add_argument('--set-admin', help='Promote an existing account; server operator only')
    parser.add_argument('--admin', action='store_true')
    parser.add_argument('--require-login', action='store_true', help='Override temporary mode and enforce login/locks')
    parser.add_argument('--temporary-password', action='store_true', help='Allow a 4-character temporary password in temporary editing mode')
    args = parser.parse_args()
    settings = json.loads(Path(__file__).with_name('settings.json').read_text())
    suspended = settings.get('admin_suspended') is True
    if suspended and (args.reserve_admin or args.set_admin or args.admin or args.require_login):
        parser.error('관리 기능이 일시 중지되어 있습니다. 관리 체계를 재개한 후 사용할 수 있습니다.')
    if args.temporary_password and (settings.get('temporary_open') is not True or args.require_login):
        parser.error('임시 비밀번호는 임시 편집 모드에서만 등록할 수 있습니다.')
    initialize(args.db)
    if args.reserve_admin or args.set_admin:
        with connect(args.db) as db:
            for username in args.reserve_admin:
                if not username.strip() or len(username) > 60:
                    parser.error('관리자 아이디는 1~60자여야 합니다.')
                db.execute('INSERT OR IGNORE INTO users(username,salt,password_hash,admin) VALUES(?,?,?,1)',
                           (username.strip(), secrets.token_hex(16), ''))
                db.execute('UPDATE users SET admin=1 WHERE username=?', (username.strip(),))
            if args.set_admin:
                if not db.execute('UPDATE users SET admin=1 WHERE username=?', (args.set_admin,)).rowcount:
                    parser.error('해당 계정이 없습니다.')
        print('관리자 지정이 저장되었습니다. 비밀번호가 없는 예약 계정은 --create-user로 활성화하세요.')
        return
    if args.create_user:
        password = getpass.getpass('비밀번호: ')
        if password != getpass.getpass('비밀번호 확인: '):
            parser.error('비밀번호가 일치하지 않습니다.')
        try:
            create_user(args.db, args.create_user, password, args.admin, args.temporary_password)
        except (ValueError, sqlite3.IntegrityError) as error:
            parser.error(str(error))
        print('계정이 생성되었습니다.')
        return
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.db_path, server.secure_cookies = args.db, args.secure_cookies
    server.admin_suspended = suspended
    server.temporary_open = suspended or (settings.get('temporary_open') is True and not args.require_login)
    server.open_csrf = secrets.token_urlsafe(32)
    print(f'Department server listening on port {args.port}', flush=True)
    server.serve_forever()


if __name__ == '__main__':
    main()
