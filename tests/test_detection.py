from app.detection import load_rules, matching_rules, rule_matches

def test_powershell_rule_matches():
    event = {"event_type":"process_creation", "process_name":"powershell.exe", "command_line":"powershell.exe", "username":"test"}
    ids = {r["id"] for r in matching_rules(event)}
    assert "AM-001" in ids

def test_normal_login_does_not_match_failed_login():
    event = {"event_type":"successful_login", "process_name":"explorer.exe", "command_line":"", "username":"test"}
    ids = {r["id"] for r in matching_rules(event)}
    assert "AM-002" not in ids

def test_suspicious_command_matches():
    event = {"event_type":"process_creation", "process_name":"powershell.exe", "command_line":"DownloadString", "username":"test"}
    ids = {r["id"] for r in matching_rules(event)}
    assert "AM-003" in ids

def test_encoded_command_matches():
    event = {"event_type":"process_creation", "process_name":"powershell.exe", "command_line":"powershell.exe -EncodedCommand SQBFAFgA", "username":"attacker"}
    ids = {r["id"] for r in matching_rules(event)}
    assert "AM-004" in ids

def test_encoded_command_does_not_match_normal_command():
    event = {"event_type":"process_creation", "process_name":"powershell.exe", "command_line":"powershell.exe -NoProfile", "username":"alice"}
    ids = {r["id"] for r in matching_rules(event)}
    assert "AM-004" not in ids

def test_detection_pack_contains_ten_mapped_rules():
    rules = load_rules()

    assert len(rules) == 12
    assert all(rule.get("attack_technique_id") for rule in rules)

def test_new_source_rules_match_sample_event_types():
    event_types = {
        "ssh_failed_login": "AM-005",
        "sudo_command": "AM-006",
        "account_created": "AM-007",
        "scheduled_task_created": "AM-008",
        "service_installed": "AM-009",
        "cloud_console_login": "AM-010",
        "lsass_access_signal": "AM-011",
        "cloud_role_assigned": "AM-012",
    }

    for event_type, expected_rule in event_types.items():
        ids = {
            rule["id"]
            for rule in matching_rules({"event_type": event_type})
        }
        assert expected_rule in ids

def test_detection_rules_do_not_match_unrelated_event():
    assert matching_rules({
        "event_type": "ordinary_file_read",
        "username": "student",
        "source_ip": "192.0.2.50",
        "process_name": "notepad.exe",
        "command_line": "notepad.exe notes.txt",
        "message": "Synthetic benign lab activity",
    }) == []
