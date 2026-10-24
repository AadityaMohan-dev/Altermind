from pathlib import Path
import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

def load_rules():
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        with path.open(encoding="utf-8") as f:
            rule = yaml.safe_load(f)
        if rule and rule.get("detection", {}).get("condition") == "selection":
            rules.append(rule)
    return rules

def rule_matches(rule, event: dict) -> bool:
    selection = rule.get("detection", {}).get("selection", {})
    for expression, expected in selection.items():
        if "|" in expression:
            field, modifier = expression.split("|", 1)
        else:
            field, modifier = expression, "equals"
        actual = str(event.get(field, ""))
        expected = str(expected)
        if modifier == "endswith" and not actual.lower().endswith(expected.lower()):
            return False
        if modifier == "contains" and expected.lower() not in actual.lower():
            return False
        if modifier == "equals" and actual.lower() != expected.lower():
            return False
        if modifier not in {"endswith", "contains", "equals"}:
            return False
    return bool(selection)

def matching_rules(event: dict):
    return [rule for rule in load_rules() if rule_matches(rule, event)]
