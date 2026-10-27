"""Read-only Microsoft Graph collection.

Sign-in uses the OAuth 2.0 device code flow. The access token stays in memory
and is sent only to graph.microsoft.com. Pagination links on any other origin
are refused, as are HTTP redirects.
"""

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from .analyze import SNAPSHOT_SCHEMA, FAILING_STATES

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
# Microsoft Graph Command Line Tools: Microsoft's public client used by Graph PowerShell.
DEFAULT_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
SCOPES = [
    "https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All",
    "https://graph.microsoft.com/DeviceManagementConfiguration.Read.All",
]
DEVICE_FIELDS = "id,deviceName,operatingSystem,osVersion,userPrincipalName,lastSyncDateTime,complianceState"
RETRYABLE = (429, 503, 504)


class GraphError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _default_open():
    return urllib.request.build_opener(_NoRedirect()).open


def _check_origin(url, allowed):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.netloc != allowed or parts.username or parts.password:
        raise GraphError("Refusing to send credentials to an unexpected origin")


def _post_form(url, fields, opener, timeout=30):
    _check_origin(url, "login.microsoftonline.com")
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with opener(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        try:
            return json.load(exc)
        except ValueError:
            raise GraphError("Sign-in request failed with HTTP %d" % exc.code) from None


def device_code_token(tenant, client_id=DEFAULT_CLIENT_ID, opener=None, out=sys.stderr,
                      sleep=time.sleep, clock=time.monotonic):
    opener = opener or _default_open()
    tenant = urllib.parse.quote(tenant or "organizations", safe="")
    base = "%s/%s/oauth2/v2.0" % (LOGIN, tenant)
    start = _post_form(base + "/devicecode", {"client_id": client_id, "scope": " ".join(SCOPES)}, opener)
    if "device_code" not in start:
        raise GraphError("Sign-in could not start: " + str(start.get("error", "unknown error")))
    print(start.get("message") or "Open %s and enter %s" % (start.get("verification_uri"), start.get("user_code")), file=out)
    interval = int(start.get("interval", 5))
    deadline = clock() + int(start.get("expires_in", 900))
    while clock() < deadline:
        sleep(interval)
        result = _post_form(base + "/token", {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": start["device_code"],
        }, opener)
        if result.get("access_token"):
            return result["access_token"]
        error = result.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        raise GraphError("Sign-in failed: " + str(error or "unknown error"))
    raise GraphError("Sign-in timed out")


class GraphClient:
    def __init__(self, token, opener=None, sleep=time.sleep, max_pages=2000):
        if not token or any(ch.isspace() for ch in token):
            raise GraphError("A single access token is required")
        self._token = token
        self._open = opener or _default_open()
        self._sleep = sleep
        self.max_pages = max_pages
        self.requests = 0

    def _get(self, url):
        _check_origin(url, "graph.microsoft.com")
        for attempt in range(6):
            req = urllib.request.Request(url, headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/json",
            })
            self.requests += 1
            try:
                with self._open(req, timeout=60) as resp:
                    return json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code in RETRYABLE and attempt < 5:
                    try:
                        wait = float(exc.headers.get("Retry-After") or 2 ** attempt)
                    except ValueError:
                        wait = 2 ** attempt
                    self._sleep(min(max(wait, 1.0), 60.0))
                    continue
                hint = {401: "token expired or invalid", 403: "missing permission or admin consent"}.get(exc.code, "")
                raise GraphError(("Graph returned HTTP %d %s" % (exc.code, hint)).strip()) from None
            except urllib.error.URLError as exc:
                raise GraphError("Could not reach Microsoft Graph: " + type(exc.reason).__name__) from None
        raise GraphError("Graph kept throttling the request")

    def pages(self, url):
        items, seen = [], set()
        for _ in range(self.max_pages):
            if url in seen:
                raise GraphError("Graph returned a pagination loop")
            seen.add(url)
            page = self._get(url)
            if not isinstance(page, dict) or not isinstance(page.get("value"), list):
                raise GraphError("Graph response had no value array")
            items.extend(page["value"])
            url = page.get("@odata.nextLink")
            if url is None:
                return items
            if not isinstance(url, str):
                raise GraphError("Graph returned an invalid next link")
        raise GraphError("Too many pages")


def collect(client, now, progress=None):
    """Build a snapshot from three read-only Graph collections."""
    say = progress or (lambda message: None)
    raw_devices = client.pages(GRAPH + "/deviceManagement/managedDevices?$select=" + DEVICE_FIELDS)
    say("Read %d managed devices" % len(raw_devices))
    summaries = client.pages(GRAPH + "/deviceManagement/deviceCompliancePolicySettingStateSummaries")
    failing = [s for s in summaries if sum(int(s.get(k) or 0) for k in
               ("nonCompliantDeviceCount", "errorDeviceCount", "conflictDeviceCount")) > 0]
    say("%d of %d compliance settings have failing devices" % (len(failing), len(summaries)))
    states = []
    for i, summary in enumerate(failing, 1):
        url = "%s/deviceManagement/deviceCompliancePolicySettingStateSummaries/%s/deviceComplianceSettingStates" % (
            GRAPH, urllib.parse.quote(str(summary.get("id", "")), safe=""))
        for s in client.pages(url):
            if s.get("state") in FAILING_STATES and s.get("deviceId") and (s.get("setting") or summary.get("setting")):
                states.append({
                    "device_id": s["deviceId"],
                    "setting": s.get("setting") or summary.get("setting"),
                    "setting_name": s.get("settingName") or summary.get("settingName") or "",
                    "platform": summary.get("platformType") or "",
                    "state": s["state"],
                })
        say("Read setting %d of %d" % (i, len(failing)))
    devices = [{
        "id": d["id"],
        "name": d.get("deviceName") or "",
        "platform": d.get("operatingSystem") or "",
        "os_version": d.get("osVersion") or "",
        "user": d.get("userPrincipalName") or "",
        "last_sync": d.get("lastSyncDateTime") or "",
        "compliance_state": d.get("complianceState") or "",
    } for d in raw_devices if isinstance(d, dict) and d.get("id")]
    return {
        "schema": SNAPSHOT_SCHEMA,
        "source": "microsoft-graph",
        "collected_at": now.isoformat().replace("+00:00", "Z"),
        "devices": devices,
        "setting_states": states,
    }
