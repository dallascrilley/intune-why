import io
import json
import urllib.error


def snapshot(devices, states, collected_at="2026-10-27T00:00:00Z"):
    return {"schema": "intune-why/snapshot@1", "collected_at": collected_at, "source": "test",
            "devices": devices, "setting_states": states}


def device(id, platform="Windows", last_sync="2026-10-26T00:00:00Z", state="noncompliant", name=None, user=None):
    return {"id": id, "name": name or id.upper(), "platform": platform, "user": user or id + "@example.test",
            "last_sync": last_sync, "compliance_state": state}


def failing(device_id, setting, state="nonCompliant"):
    return {"device_id": device_id, "setting": setting, "setting_name": setting.rsplit(".", 1)[-1], "state": state}


class FakeHTTP:
    """Scripted opener: each entry is (status, body_dict, headers)."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        status, body, headers = self.responses.pop(0)
        data = io.BytesIO(json.dumps(body).encode())
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "error", headers or {}, data)
        return data
