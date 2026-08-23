"""The Strands agents themselves.

Intake holds a token scoped to ["read", "export"]. It can read documents and request exports
itself, but delegates summarizing to a fresh sub-agent (Summarizer) via a real second-hop token
exchange, deliberately narrowed to ["read"] even though Intake itself could export. The point
being demonstrated: that narrowing is enforced by the token's own scope at the gateway, not by
Summarizer's good behavior — if its model ever tried to call something export-shaped, the token
itself cannot do it, checked before any policy question is even asked.
"""
from __future__ import annotations

from strands import Agent, tool
from strands.models.anthropic import AnthropicModel

from demo.warrant_client import WarrantClient

MODEL_ID = "claude-sonnet-5"


def _model() -> AnthropicModel:
    return AnthropicModel(model_id=MODEL_ID, max_tokens=1024)


def make_read_tool(client: WarrantClient, token: str):
    @tool
    def read_document(doc_id: str) -> str:
        """Read a case document's content through warrant's authorization gateway.

        Args:
            doc_id: the document identifier, e.g. "doc:123"
        """
        result = client.gateway_read(token=token, doc_id=doc_id)
        if result["decision"] == "PERMIT":
            return result["content"]
        return f"Access denied ({result['decision']}): {result['reason']}"

    return read_document


def make_summarizer_agent(client: WarrantClient, scoped_token: str) -> Agent:
    return Agent(
        model=_model(),
        system_prompt=(
            "You are Summarizer, a sub-agent with read-only access to exactly one case document. "
            "Read it and produce a single, concise sentence summarizing it. You do not have "
            "export access and should not claim to — if asked to do anything beyond reading, "
            "say plainly that it's outside your delegated scope."
        ),
        tools=[make_read_tool(client, scoped_token)],
        name="Summarizer",
    )


def make_delegate_tool(client: WarrantClient, parent_token: str, sub_bootstrap_token: str):
    @tool
    def delegate_to_subagent(doc_id: str) -> str:
        """Delegate summarizing one document to a fresh, narrowly-scoped Summarizer sub-agent.

        This mints a real second-hop authorization token for the sub-agent, deliberately narrowed
        to read-only even though you may hold export access yourself — the sub-agent's token
        cannot be widened later, regardless of what it is asked to do. Returns the sub-agent's
        summary as plain text.

        Args:
            doc_id: the document identifier to summarize, e.g. "doc:123"
        """
        sub_identity = client.issue_identity("B1", bootstrap_token=sub_bootstrap_token)
        scoped_token = client.exchange_chained(
            parent_token=parent_token,
            sub_actor_cert_pem=sub_identity["cert_pem"],
            requested_actions=["read"],
        )
        summarizer = make_summarizer_agent(client, scoped_token)
        result = summarizer(f"Please read and summarize {doc_id}.")
        return str(result)

    return delegate_to_subagent


def make_request_export_tool(client: WarrantClient, token: str):
    @tool
    def request_export(doc_id: str) -> str:
        """Request to export a document. This may require human approval before it actually
        completes. If it does, report that back plainly and stop — do not retry in a loop, and
        do not claim the export succeeded until the tool result says PERMIT with content.

        Args:
            doc_id: the document identifier to export, e.g. "doc:123"
        """
        result = client.gateway_export(token=token, doc_id=doc_id)
        if result["decision"] == "PERMIT":
            return f"Export completed: {result['content']}"
        if result["decision"] == "REQUIRE_APPROVAL":
            return (
                f"Export requires human approval (obligation_id={result['obligation_id']}). "
                "Not completed yet."
            )
        return f"Export denied ({result['decision']}): {result['reason']}"

    return request_export


def make_intake_agent(client: WarrantClient, token: str, sub_bootstrap_token: str) -> Agent:
    return Agent(
        model=_model(),
        system_prompt=(
            "You are Intake, an agent acting on behalf of Rick to review case documents. "
            "You may read documents and request exports yourself, but for any document that "
            "needs summarizing, delegate that specific work to delegate_to_subagent rather than "
            "doing it yourself. Be concise in your final responses."
        ),
        tools=[
            make_read_tool(client, token),
            make_delegate_tool(client, token, sub_bootstrap_token),
            make_request_export_tool(client, token),
        ],
        name="Intake",
    )
