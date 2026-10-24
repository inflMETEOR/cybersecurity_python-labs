import sys
from labs.lab02.task1 import Admin, AuditLog, Session, User, UserAccount


def demo():
    user1 = User("ted", "Fdkdkdk@gmail.com", "employer", True)
    user1.set_password("MySecret123!")
    print(user1)
    try:
        user1.email = "good_email"
    except ValueError as e:
        print(f"Успішно відловлено помилку email: {e}")

    user1.set_password("1234567890")
    admin1 = Admin(
        "misha",
        "admin@gmail.com",
        True,
        permissions={
            "permision_to_personal_data",
            "permision_to_server",
            "permision_to_money",
        },
    )
    print(f"Список дозволів адміна: {admin1.permissions}")
    admin1.grant_permission("permision_for_test")
    admin1.revoke_permission("permision_to_money")
    print(admin1.has_permission("permision_to_money"))
    print(admin1)

    account = UserAccount(user=user1)

    result_fail = account.login("ted", "wrong_password", "192.168.1.1")
    print(f"Результат входу з неправильним паролем: {result_fail}")
    true_password = account.login("ted", "1234567890", "192.168.1.1")
    print(f"Result with right password: {true_password}")
    account.logout()
    print("Записи в журналі аудиту:")
    account["audit_log"].show_all()


if __name__ == "__main__":
    demo()
