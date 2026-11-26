#!/usr/bin/env python3
"""Create /etc/node-admin/admin.json. Usage: make-admin.py [password]"""
import base64, hashlib, json, os, secrets, sys

PATH = '/etc/node-admin/admin.json'
ITER = 310000

password = sys.argv[1].strip() if len(sys.argv) > 1 and sys.argv[1].strip() else None
generated = password is None
if generated:
    alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    password = ''.join(secrets.choice(alphabet) for _ in range(18))
if len(password) < 10:
    raise SystemExit('密码至少 10 个字符')

salt = secrets.token_bytes(16)
digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITER, 32)
payload = {
    'username': 'admin',
    'salt': base64.urlsafe_b64encode(salt).decode().rstrip('='),
    'password_hash': base64.urlsafe_b64encode(digest).decode().rstrip('='),
    'iterations': ITER,
}
os.makedirs('/etc/node-admin', mode=0o700, exist_ok=True)
with open(PATH, 'w', encoding='utf-8') as handle:
    json.dump(payload, handle, ensure_ascii=False, indent=2)
os.chmod(PATH, 0o600)
print(password if generated else 'admin.json 已更新')
