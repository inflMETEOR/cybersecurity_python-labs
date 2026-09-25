import sys
import os
import random
import string
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
'../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

passwords = ["Hello123!", "simple", "CompL3x@Pass", "password", "Str0ng#2023",
"weak", "MySecur3!", "12345", "Advanced@1", "basic"]
criteria = {"min_length": 10, "require_digits": True, "require_upper": True,
"require_special": True}
forbidden_passwords = {"password", "simple", "weak", "basic", "12345", "hello"}

random_indices = random.sample(range(len(passwords)), 3)
random_passwords = [passwords[i] for i in random_indices]
passwords += random_passwords

def password_validation (password, criteria, forbidden_passwords):

    if password in forbidden_passwords or len(password) < criteria["min_length"]:
        return "Password is Forbidden"

    count_true = 0
    
    if criteria["require_digits"] and any(c.isdigit() for c in password):
        count_true += 1

    if len(password) >= criteria["min_length"] + 4:
        count_true += 1
    
    if criteria["require_upper"] and any(c.isupper() for c in password):
        count_true += 1 

    if any(c.islower() for c in password):
            count_true += 1 
    
    if criteria["require_special"] and any(c in string.punctuation for c in password):
        count_true += 1 

    if count_true == 5 and passwords.count(password) == 1:
        return "Дуже сильний"
    elif count_true == 5 or (count_true == 4 and len(password) >= criteria["min_length"]):
        return "Сильний"
    elif count_true in (2,3,):
        return "Середній"
    else:
        return "Слабкий"

print("------------")
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)
print("------------")
print(    )
print(f"{'Пароль':<20} | {'Статус':<20}")
print("-" * 43)


for password in passwords:
    status = password_validation (password, criteria, forbidden_passwords)
    print(f"{password:<20} | {status:<20}")
