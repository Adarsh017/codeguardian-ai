"""Notification service: logs every scan result and optionally posts to a webhook
(Slack / Discord / Microsoft Teams / generic JSON)."""
import logging

import httpx

from ..config import settings

log = logging.getLogger("codeguardian.notify")


def notify_scan(project: str, scan_id: int, status: str, scores: dict | None, counts: dict | None,
                gate: dict | None, error: str = "") -> None:
    if status == "completed":
        text = (f"CodeGuardian AI scan #{scan_id} for '{project}' completed - "
                f"security {scores['security_score']:.0f}/100, quality {scores['quality_score']:.0f}/100, "
                f"{counts.get('Critical', 0)} critical / {counts.get('High', 0)} high. "
                f"Quality gate: {'PASSED' if gate['passed'] else 'FAILED'}.")
    else:
        text = f"CodeGuardian AI scan #{scan_id} for '{project}' failed: {error[:200]}"
    log.info(text)
    if settings.NOTIFY_WEBHOOK_URL:
        try:
            httpx.post(settings.NOTIFY_WEBHOOK_URL, json={"text": text, "content": text}, timeout=10)
        except httpx.HTTPError as exc:
            log.warning("Webhook notification failed: %s", exc)
