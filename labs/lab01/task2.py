import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
'../../')))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

users = {
 "admin001": {"role": "administrator", "clearance": 4, "department": "IT",
"active": True},
 "user123": {"role": "analyst", "clearance": 2, "department": "Security",
"active": True},
 "guest789": {"role": "guest", "clearance": 1, "department": "External",
"active": True},
 "manager456": {"role": "manager", "clearance": 3, "department":
"Operations", "active": True},
 "contractor99": {"role": "contractor", "clearance": 1, "department":
"External", "active": False}
}

resources = [("database_backup", 4), ("user_logs", 2), ("public_docs", 1),
("financial_reports", 3), ("system_config", 4), ("training_materials", 1),
("security_policies", 3), ("audit_logs", 4), ("employee_data", 3),
("temp_files", 1)]

security_levels = ("Public", "Internal", "Confidential", "Secret")
blocked_users = {"contractor99", "temp_user", "suspended_acc"}

# for item in resources:
#     name = item[0]
#     level_num = item[1]
    
#     if level_num == 1:
#         level_name = security_levels[0]
#     elif level_num == 2:
#         level_name = security_levels[1]
#     elif level_num == 3:
#         level_name = security_levels[2]
#     elif level_num == 4:
#         level_name = security_levels[3]
        
#     print(f"{name}: {level_name}")

# for name, level in resources:
#     level_name = security_levels[level - 1]
#     print(f"{name} - {level_name}")
print("------------")
print(STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)
print("------------")


levels_map = { # створив словник з ключем це рівень доступу і значенням назвою рівня
    1: "Public",
    2: "Internal",
    3: "Confidential",
    4: "Secret"
}

for name, level in resources: # замінив через ключ число захищеності на назву рівня захищ
    level_name = levels_map[level]
    print(f"{name} - {level_name}")

print("----------------")
print("----------------")

for username, user_info in users.items():

    print(f"user = {username.upper()}")
    print()

    if username in blocked_users:
        print("DENY (User is blocked)")
        continue
        
    if user_info["active"] == False:
        print("DENY (Account inactive)")
        continue
        
    for res_name, res_level in resources:
        if user_info["clearance"] >= res_level:
            print(f" resources =  {res_name}: ALLOW")
        else:
            print(f" resources = {res_name}: DENY (Insufficient clearance)")
    print()

    


