import sys
import os
import random
import hashlib
import hmac
import re
from datetime import datetime
from datetime import timezone
from datetime import timedelta
from dataclasses import dataclass

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER
ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900
ALLOWED_KEYS = ["user", "session", "audit_log"]

class User:
    def __init__(self, username: str , email: str , role: str , active: bool, ):
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = None
        self.__password_salt = None
    @property
    def email(self) -> str:
        return self.__email
    @email.setter
    def email(self, value: str):
        pattern = r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний email: {value}")
        self.__email = value
    def set_password(self, password: str):
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)
        self.__password_hash = key.hex()
        self.__password_salt = salt.hex()
    def check_password(self, password: str) -> bool:
        salt_bytes = bytes.fromhex(self.__password_salt) #перетворюєм hex назад в байти 
        key_bytes_initial = bytes.fromhex(self.__password_hash)
        key_enter = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, ITERATIONS)
        return hmac.compare_digest(key_enter, key_bytes_initial)
    def deactivate(self):
        self.active = False
    def __str__(self):
        return f"Юзер з ніком: {self.username}, має email: {self.email}, роль: {self.role}, Активність:{self.active}"
   
class Admin(User):
    def __init__(self, username: str, email: str, active: bool = True, permissions: list | set | None = None):
        super().__init__(username=username, email=email, role="admin", active=active)
        self.permissions = set(permissions) if permissions else set()

    def grant_permission(self, permission: str):
        self.permissions.add(permission)  

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission)  

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions 

    def __str__(self) -> str:
        base_info = super().__str__()
        perms_str = ", ".join(sorted(self.permissions)) if self.permissions else "немає"
        return f"{base_info}, Дозволи: [{perms_str}]"

class Session:
    def __init__(self, ip: str, login_time: datetime | None = None, last_activity: datetime | None = None):
        self.ip = ip
        self.login_time = login_time or datetime.now(timezone.utc)
        self.last_activity = last_activity or datetime.now(timezone.utc)

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути більшим за 0")
        elapsed_time = datetime.now(timezone.utc) - self.last_activity
        return elapsed_time < timedelta(seconds=timeout_sec)

@dataclass
class LogEntry:
    timestamp: datetime
    username: str
    action: str

class AuditLog:
    def __init__(self, logs: list | None = None):
        self.logs = list(logs) if logs else []

    def add_log(self, username: str, action: str):
        current_time = datetime.now(timezone.utc)
        new_entry = LogEntry(timestamp=current_time, username=username, action=action)
        self.logs.append(new_entry)

    def show_all(self):
        for log in self.logs:
            print(log)

class UserAccount:
    def __init__(self, user: User, session: Session | None = None, audit_log: AuditLog | None = None):
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log else AuditLog()
    def login(self, username, password, ip):
        if self.user.active and self.user.check_password(password) and username == self.user.username:
            self.session = Session(ip=ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True
        else:
            self.audit_log.add_log(username, "login_failure")
            return False

    def is_authenticated(self):
        if not self.session: return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self):
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None
    
    def __getitem__(self, key):
        if key not in ALLOWED_KEYS:
            raise KeyError(f"Ключ '{key}' недоступний або не існує")

        if key == "user":
            return self.user
        if key == "session":
            return self.session
        if key == "audit_log":
            return self.audit_log
        
    def __setitem__(self, key: str, value):
        if key not in ALLOWED_KEYS:
            raise KeyError(f"Ключ '{key}' недоступний або не існує")

        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' має бути екземпляром класу User")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення для 'session' має бути екземпляром класу Session або None"
                )
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError(
                    "Значення для 'audit_log' має бути екземпляром класу AuditLog"
                )
            self.audit_log = value        

        


