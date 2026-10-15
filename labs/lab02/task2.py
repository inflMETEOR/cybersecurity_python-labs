import json
from pathlib import Path
import re
from collections import defaultdict
import argparse

BASE_DIR = Path(__file__).resolve().parent
FILE_PATH = BASE_DIR / "data" / "firewall_rules.json"

def open_json_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            rules = json.load(file)
            return rules
    except FileNotFoundError:
        print("No file")
        return []


def check_ip_address(address):
    patern = r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
    check_ip = bool(re.fullmatch(patern, str(address))) # поверне булеве значення 
    return check_ip

def check_source(source):
    pattern = r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\/(?:3[0-2]|[12]?\d))?$"
    check_source = bool(re.fullmatch(pattern, str(source))) #перетвор на рядок якщо ip, source пусті
    return check_source

def sort_rule(rules):
    valid_data = []
    wrong_validation_number = 0
    for rule in rules:
        ip_address = rule.get("destination")
        source = rule.get("source")
        if check_ip_address(ip_address) and check_source(source):
            valid_data.append(rule)
        else:
            wrong_validation_number += 1

    return valid_data, wrong_validation_number

def find_odds(rules):
    default_dict = defaultdict(list)
    for rule in rules: 
        source = rule.get("source")
        destination = rule.get("destination")
        port = rule.get("port")

        key = (source, destination, port)
        default_dict[key].append(rule)

    return default_dict

def compared_odds(rules):
    new_list_without_odds = []
    dublicat_rules = 0
    conflicting_rules = 0
    for rule in rules.values():
        if len(rule) == 1:
            new_list_without_odds.append(rule[0])
        else:
            action_set = {r.get("action") for r in rule}
            if len(action_set) == 1:
                dublicat_rules += len(rule) - 1
                new_list_without_odds.append(rule[0])
            else:
                conflicting_rules += 1

    return new_list_without_odds, dublicat_rules, conflicting_rules

def hight_risk_rules(the_one_list):
    hight_risk_rules_conteiner = []
    for the_one_rule in the_one_list:
        action = the_one_rule.get("action")
        source = the_one_rule.get("source")
        port = the_one_rule.get("port")
        # if action == "ALLOW" and (source in ["0.0.0.0/0", "ANY", "Any"] or port in ["ANY", "Any", "*"]):
        #     hight_risk_rules_conteiner.append(the_one_rule)

        if action == "ALLOW":
            reasons = []
            
            if source in ["0.0.0.0/0", "ANY"]:
                reasons.append("Unlimited exposure (Public Source)")
                
            if port in ["ANY", "*"]:
                reasons.append("All ports allowed (ANY port)")
                
            if reasons:
                risk_info = {
                    "rule_id": the_one_rule.get("id"),
                    "rule": the_one_rule,
                    "reason": ", ".join(reasons)
                }
                hight_risk_rules_conteiner.append(risk_info)

    return hight_risk_rules_conteiner

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Firewall Rule Auditor — аналізатор та очисник правил фаєрволу."
    )

    parser.add_argument(
        "--rules-file",
        type=str,
        default="data/rules.json",
        help="Шлях до вхідного JSON-файлу з правилами (за замовчуванням: data/rules.json)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/cleaned_rules.json",
        help="Шлях для збереження очищених правил (за замовчуванням: data/cleaned_rules.json)",
    )
    parser.add_argument(
        "--check-conflicts",
        action="store_true",
        help="Увімкнути детальний аналіз та відсіювання конфліктних правил",
    )

    return parser.parse_args()


def save_json_file(file_path, data):
    path = Path(file_path)

    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)

def print_audit_report(
    total_rules,
    invalid_count,
    dublicat_rules,
    conflicting_rules,
    cleaned_rules,
    high_risk_list,
):
    print("\n" + "=" * 55)
    print("           FIREWALL RULES AUDIT REPORT           ")
    print("=" * 55)

    print("\n[СТАТИСТИКА ПЕРЕВІРКИ]")
    print(f"  • Всього завантажено правил:       {total_rules}")
    print(f"  • Невалідні IP / Маски (видалено): {invalid_count}")
    print(f"  • Дублікати (видалено повторки):  {dublicat_rules}")
    print(f"  • Конфліктні правила (відсіяно):  {conflicting_rules}")
    print(
        f"  -------------------------------------------------"
    )
    print(f"  • Залишилось валідних правил:      {len(cleaned_rules)}")

    print("\n[ПОТЕНЦІЙНО НЕБЕЗПЕЧНІ ПРАВИЛА (HIGH-RISK)]")
    if high_risk_list:
        for item in high_risk_list:
            rule_id = item.get("rule_id")
            rule = item.get("rule")
            reason = item.get("reason")
            print(
                f"  [HIGH-RISK] Rule #{rule_id}: {rule.get('action')} "
                f"{rule.get('source')} -> {rule.get('destination')}:{rule.get('port')} "
                f"({reason})"
            )
    else:
        print("  Критичних ризиків не виявлено.")

    print("\n" + "=" * 55 + "\n")


if __name__ == "__main__":
    firewall_rules = open_json_file(FILE_PATH)
    valid_rules, invalid_count = sort_rule(firewall_rules)
    default_dict = find_odds(valid_rules)
    new_list_without_odds, dublicat_rules, conflicting_rules = compared_odds(default_dict)
    hight_risk_rules_conteiner = hight_risk_rules(new_list_without_odds)
    output_path = BASE_DIR / "data" / "cleaned_rules.json"
    save_json_file(output_path, new_list_without_odds)
    print_audit_report(
        total_rules=len(firewall_rules),
        invalid_count=invalid_count,
        dublicat_rules=dublicat_rules,
        conflicting_rules=conflicting_rules,
        cleaned_rules=new_list_without_odds,
        high_risk_list=hight_risk_rules_conteiner,
    )
            