from datetime import datetime
import csv
import hashlib
import json
import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

print("------------")
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)
print("------------")

# Сіль з 5 символів з нулями зліва за варіантом
SALT = f"{VARIANT_NUMBER:0>5}"


class ValidationError(Exception):
    pass


def generate_hash(
    password: str, salt: str = SALT
) -> str:  # поверне рядок захешованого паролю
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми!")
    elif len(password) < 10:
        raise ValidationError("Password is too short")
    # конкатенація(обєднання salt і пароля)
    # перетворюєм те що вийшло в байти бо hashlib працює онлі з ними
    data_to_hash = (password + salt).encode("utf-8")
    # через hashlib вибираєм як саме будем перетворювати наш масив байтів і передаєм його
    # hexdigest читає оброблений хеш з мин рядка і перетворює його в норм рядок.
    return hashlib.sha3_224(data_to_hash).hexdigest()


users_to_register = (
    ("user_alpha", "Password12345"),
    ("user_beta", "SecurePass2026"),
    ("user_gamma", "Short1"),  # Коророткий пароль для тесту валідації
    ("user_delta", "MySecretPass99"),
    ("user_epsilon", "StrongP@ssw0rd!"),
    ("user_zeta", "qwerty123456"),
    ("user_eta", "SuperSecure321"),
    ("user_theta", "TestPass100500"),
    ("user_iota", ""),  # Порожній пароль для тесту ValueError
    ("user_kappa", "ValidPass98765"),
)


# Створення одинчки запису (Пункт 3 вимог)
def create_user(
    username: str, password: str
) -> tuple:  # поверне кортеж:імя, хеш_пароль
    hashed_pass = generate_hash(password, salt=SALT)
    return (username, hashed_pass)


# Запис усієї бази у CSV
def creates_user(users_data: tuple):
    path_folder = "labs/lab01/data"  # шлях де буде створюватися папка
    file_path = os.path.join(
        path_folder, "users.csv"
    )  # підстав прав розідлювач для шляху файлу

    processed_users = []
    for user_name, user_password in users_data:
        try:
            user_entry = create_user(user_name, user_password)
            processed_users.append(user_entry)
        except (ValueError, ValidationError) as e:
            print(f"[ПРОПУЩЕНО ВАЛІДАЦІЮ] Користувач '{user_name}': {e}")

    try:
        os.makedirs(path_folder, exist_ok=True)
        with open(file_path, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(
                file
            )  # перекладає списки в коректний формат cvs роюлячи переноси,коми
            writer.writerow(
                ["login", "password_hash"]
            )  # тупо заголовок після якого буде вже масив
            writer.writerows(
                processed_users
            )  # завдяки writerows записує кортеж в стовп по два розділяючи
        print("\n[УСПІХ] Базу даних CSV створено.")
    except (PermissionError, IOError) as e:
        print(f"ПОМИЛКА ФАЙЛУ: {e}")


def load_and_print_users() -> list:
    file_path = "labs/lab01/data/users.csv"
    users_db = []

    try:
        with open(file_path, mode="r", newline="", encoding="utf-8") as file:
            reader = csv.reader(file)
            header = next(reader, None)  # Безопечний перехід

            for row in reader:
                if row:  # Перевірка на порожні рядки
                    users_db.append(row)  # Зберігаю у users_db

        print(f"\n{'User':<15} | {'Password Hash'}")
        print("-" * 70)
        for login_name, password_hash in users_db:
            print(f"{login_name:<15} | {password_hash}")

    except FileNotFoundError:
        print(f"[ПОМИЛКА] Файл {file_path} не знайдено!")
    except (PermissionError, IOError) as e:
        print(f"[ПОМИЛКА ФАЙЛУ] Помилка зчитування CSV: {e}")

    return users_db


def log_event(func):
    def wrapper(*args, **kwargs):
        path_folder = "labs/lab01/data"
        file_path = os.path.join(path_folder, "log.json")

        result_bool = False
        try:
            result_bool = func(*args, **kwargs)
        except Exception as e:
            result_bool = False
            raise e
        finally:
            status = "success" if result_bool else "failure"
            username = args[0] if args else kwargs.get("username", "unknown")

            log_entry = {
                "event": "login",
                "user": username,
                "result": status,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            try:
                os.makedirs(path_folder, exist_ok=True)
                logs = []
                if os.path.exists(file_path):
                    try:
                        with open(
                            file_path, mode="r", encoding="utf-8"
                        ) as json_file:
                            logs = json.load(json_file)
                    except json.JSONDecodeError:
                        logs = []

                logs.append(log_entry)
                with open(file_path, mode="w", encoding="utf-8") as json_file:
                    json.dump(logs, json_file, ensure_ascii=False, indent=4)

            except (PermissionError, IOError) as e:
                print(f"[ПОМИЛКА ЛОГУВАННЯ] Не вдалося оновити log.json: {e}")

        return result_bool

    return wrapper


@log_event
def login(
    username: str, password: str
) -> bool:  # перевірка на те чи є такий користувач чи ні
    # і чи правильний в нього захешований пароль
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми!")

    users_db = load_and_print_users()
    input_hash = generate_hash(password, salt=SALT)

    for db_username, db_password in users_db:
        if username == db_username and db_password == input_hash:
            print(f"\n[АВТОРИЗАЦІЯ] Успішний вхід для користувача: {username}")
            return True

    print(
        f"\n[АВТОРИЗАЦІЯ] Помилка входу: користувача {username} або пароль не знайдено."
    )
    return False


def main():
    print("Створення бази даних CSV")
    creates_user(users_to_register)

    print("\nТестування авторизації (Login)")
    # Успішна спроба входу
    try:
        login("user_alpha", "Password12345")
    except (ValueError, ValidationError) as e:
        print(f"Помилка: {e}")

    try:
        login("user_alpha", "WrongPassword123")
    except (ValueError, ValidationError) as e:
        print(f"Помилка: {e}")

    try:
        login("", "Password12345")
    except (ValueError, ValidationError) as e:
        print(f"[ОЧІКУВАНА ПОМИЛКА] {e}")


if __name__ == "__main__":
    main()