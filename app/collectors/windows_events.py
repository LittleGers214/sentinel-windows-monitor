import logging
from datetime import UTC, datetime
from xml.etree import ElementTree as ET

from app.database.models import EventData

log = logging.getLogger(__name__)
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event(xml):
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    fields = {n.get("Name"): n.text or "" for n in root.findall("e:EventData/e:Data", NS)}
    # Event 1102 uses UserData rather than EventData.
    for node in root.findall("e:UserData//*", NS):
        fields.setdefault(node.tag.split("}")[-1], node.text or "")

    def value(name):
        return system.findtext("e:" + name, "", NS)

    username = fields.get("TargetUserName") or fields.get("SubjectUserName", "")
    domain = fields.get("TargetDomainName") or fields.get("SubjectDomainName", "")
    if domain and domain != "-":
        username = domain + "\\" + username
    ip = fields.get("IpAddress", "")
    if ip in ("-", "::", ""):
        ip = ""
    return EventData(
        record_id=int(value("EventRecordID")),
        event_id=int(value("EventID")),
        timestamp=datetime.fromisoformat(system.find("e:TimeCreated", NS).get("SystemTime"))
        .astimezone(UTC)
        .replace(tzinfo=None),
        source=value("Computer"),
        username=username,
        ip_address=ip,
        raw_data=xml,
        channel=value("Channel") or "Security",
    )


class WindowsEvents:
    def __init__(self):
        import win32evtlog

        self.api = win32evtlog

    def _query(self, xpath, reverse=False, count=256):
        api = self.api
        flags = api.EvtQueryChannelPath | (
            api.EvtQueryReverseDirection if reverse else api.EvtQueryForwardDirection
        )
        query = api.EvtQuery("Security", flags, xpath)
        try:
            handles = api.EvtNext(query, count)
            try:
                rendered = []
                for handle in handles:
                    try:
                        rendered.append(api.EvtRender(handle, api.EvtRenderEventXml))
                    except Exception:
                        log.exception("Cannot render Windows event; skipping record")
                return rendered
            finally:
                for handle in handles:
                    handle.Close()
        except Exception as exc:
            if getattr(exc, "winerror", None) == 259:
                return []
            raise
        finally:
            query.Close()

    def poll(self, cursor):
        # Check cursor identity as well as its record ID: clearing the log can reuse IDs.
        if cursor:
            records = self._query(f"*[System[EventRecordID={int(cursor['record_id'])}]]", count=1)
            if not records or parse_event(records[0]).timestamp.isoformat() != cursor["timestamp"]:
                log.warning("Security cursor no longer available; replaying retained records")
                cursor = None
        after = int(cursor["record_id"]) if cursor else 0
        # Read all IDs so unsupported events advance the checkpoint too.
        result = []
        for xml in self._query(f"*[System[EventRecordID>{after}]]"):
            try:
                data = parse_event(xml)
                checkpoint = {"record_id": data.record_id, "timestamp": data.timestamp.isoformat()}
                result.append((data, checkpoint))
            except Exception:
                log.exception("Cannot parse Windows event")
                # Keep going; a later valid record advances the cursor.
        return result

    def latest_record(self):
        records = self._query("*", reverse=True, count=1)
        return parse_event(records[0]) if records else None
