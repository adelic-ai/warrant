"""Cedar as the permit/forbid substrate.

Per the architecture research this project is built from: Cedar is the substrate, not the
contribution — it decides one action at a time, permit/forbid only, forbid-overrides-permit as a
single fixed-priority defeater. Everything this project adds on top (obligation discharge
tracking, defeater provenance, scope non-increase across a delegation chain) stays outside Cedar,
in `sage/pdp.py`'s wrapper. This module's only job is: given a Delegation's permitted/forbidden
action lists, ask Cedar whether one specific action is allowed.

Delegations are runtime data (rows in the `delegation` table), not a static policy file, so the
Cedar PolicySet is generated per-decision from the Delegation record rather than hand-authored.
That's a real cost (no benefit from Cedar's static analyzability yet — the policy set doesn't
exist until decision time) — a fuller build would persist delegations as Cedar policies at
creation time instead of at evaluation time. Noted as a next step, not hidden.
"""
from __future__ import annotations

try:
    import cedarpy

    CEDAR_AVAILABLE = True
except ImportError:  # pragma: no cover — exercised only when the wheel truly isn't installed
    cedarpy = None  # type: ignore
    CEDAR_AVAILABLE = False


def _policy_text(subject_id: str, resource_id: str, actions: list[str], effect: str) -> str:
    lines = []
    for i, action in enumerate(actions):
        lines.append(
            f'@id("gen-{effect}-{i}")\n'
            f'{effect}(\n'
            f'    principal == Agent::"{subject_id}",\n'
            f'    action == Action::"{action}",\n'
            f'    resource == Resource::"{resource_id}"\n'
            f");"
        )
    return "\n".join(lines)


def cedar_permits(subject_id: str, action: str, resource_id: str, permitted_actions: list[str]) -> bool:
    """True iff Cedar's evaluator allows `action`, given only the permitted-action list as permit
    rules (forbidden actions are already rejected earlier in pdp.py's wrapper, before this is
    ever called — Cedar here only answers the affirmative-grant question)."""
    if not CEDAR_AVAILABLE:
        raise RuntimeError("cedarpy is not installed")
    if not permitted_actions:
        return False

    policies = _policy_text(subject_id, resource_id, permitted_actions, "permit")
    entities = [
        {"uid": {"type": "Agent", "id": subject_id}, "attrs": {}, "parents": []},
        {"uid": {"type": "Resource", "id": resource_id}, "attrs": {}, "parents": []},
    ]
    request = {
        "principal": f'Agent::"{subject_id}"',
        "action": f'Action::"{action}"',
        "resource": f'Resource::"{resource_id}"',
        "context": {},
    }
    result = cedarpy.is_authorized(request, policies, entities)
    return result.decision == cedarpy.Decision.Allow
