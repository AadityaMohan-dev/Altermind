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

