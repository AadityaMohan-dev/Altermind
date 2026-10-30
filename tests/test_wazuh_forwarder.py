import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import requests

from tools.forward_wazuh_alert import forward_alert


def test_forwarder_posts_single_alert_with_token(tmp_path: Path):
    alert_path = tmp_path / "alert.json"
    alert_path.write_text(json.dumps({"id": "test-1"}), encoding="utf-8")
    response = Mock()
    response.ok = True
    response.json.return_value = {
        "event": {"id": 7},
        "duplicate": False,
        "alerts_created": 1,
    }

    with patch("tools.forward_wazuh_alert.requests.post", return_value=response) as post:
        result = forward_alert(alert_path, "http://127.0.0.1:8000/", "test-token")

    assert result == 0
    post.assert_called_once_with(
        "http://127.0.0.1:8000/integrations/wazuh/alerts",
        json={"id": "test-1"},
        headers={"X-Wazuh-Token": "test-token"},
        timeout=15,
    )


def test_forwarder_rejects_non_object_alert_file(tmp_path: Path):
    alert_path = tmp_path / "alert.json"
    alert_path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="one JSON object"):
        forward_alert(alert_path, "http://127.0.0.1:8000", "test-token")


def test_forwarder_does_not_expose_provider_response_body(tmp_path: Path):
    alert_path = tmp_path / "alert.json"
    alert_path.write_text('{"id":"test-1"}', encoding="utf-8")
    response = Mock()
    response.ok = False
    response.status_code = 401
    response.text = "secret provider detail"

    with patch("tools.forward_wazuh_alert.requests.post", return_value=response):
        with pytest.raises(RuntimeError, match="HTTP 401") as error:
            forward_alert(alert_path, "http://127.0.0.1:8000", "test-token")

    assert "secret provider detail" not in str(error.value)
