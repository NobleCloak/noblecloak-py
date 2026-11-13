# GENERATED FILE. DO NOT EDIT BY HAND.
# Generated from dist/openapi.public.yaml of @noblecloak/spec 0.12.0 (sha256 9ff3ceb6439ccede14f8035748bfa92afff901ff9586d9058796de72749f76c7)
# by scripts/generate_models.py (datamodel-code-generator 0.92.0).
# Update the pin in conformance/, run `bun install` there and `uv run python scripts/generate_models.py`,
# and commit the result; CI fails when this file is not what that writes.

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, RootModel


class Problem(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: Annotated[str, Field(examples=["https://docs.noblecloak.com/problems/approval_conflict"])]
    title: str
    status: Annotated[int, Field(ge=400, le=599)]
    detail: str | None = None
    instance: str | None = None
    request_id: Annotated[
        str,
        Field(
            description="The id of this request, of the same kind as `meta.request_id` on a success envelope. Every problem this API produces carries one, a server failure included, and it is never empty.\n",
            min_length=1,
        ),
    ]
    max_items: Annotated[
        int | None,
        Field(
            description="Only on `batch_too_large`: the most items this deployment accepts in the batch, so a client that never read `limits` on the capabilities can split the batch and retry.\n",
            ge=1,
            le=100,
        ),
    ] = None
    retry_after_seconds: Annotated[
        int | None,
        Field(
            description="Only on `service_unavailable` and `rate_limited`, and only when the response carries the `Retry-After` header: the same number of seconds. A browser reads a response header cross-origin only if the server lists it, and it can always read the body.\n",
            ge=0,
        ),
    ] = None
    reason: Annotated[
        str | None,
        Field(
            description="Only on `service_unavailable`: a code token naming the cause. The documented value is `eligibility_lookup` (the deployment could not determine whether the caller may resolve an approval, so it answers 503 and never a digest-only view or a refusal). A client treats a well-formed value it does not know as a plain 503; a client that matches on `type` keeps working.\n",
            pattern="^[a-z][a-z0-9_]{0,63}$",
        ),
    ] = None
    max_bytes: Annotated[
        int | None,
        Field(
            description="Only on `payload_too_large`: the most bytes of body this deployment accepts, when it can say.\n",
            ge=1,
        ),
    ] = None
    policy_id: Annotated[
        str | None,
        Field(
            description="Only on `policy_conflict`: the published policy that already governs one of the (tool, subject) pairs of the policy being published.\n",
            min_length=1,
        ),
    ] = None
    rejected_approval_id: Annotated[
        str | None,
        Field(
            description="Only on `rejected_duplicate`: the most recent rejected approval, within the window, whose identity the request repeats, readable under the rules of Who sees an approval.\n",
            min_length=1,
        ),
    ] = None
    connection_id: Annotated[
        str | None,
        Field(
            description="Only on `connection_exists` (rev 11): the existing registration of the same server, when the caller may read it (see `Owner`); absent otherwise.\n",
            min_length=1,
        ),
    ] = None
    agent_id: Annotated[
        str | None,
        Field(
            description="Only on `principal_bound` (rev 13): the agent the service principal is already bound to. Always present on `principal_bound`.\n",
            min_length=1,
        ),
    ] = None
    member: Annotated[
        str | None,
        Field(
            description="Only on `unsupported_policy_form` (rev 13) and on `proposal_refused` (rev 14, where it is present when the refusal has a part of the body to name), and (rev 16) on an `invalid_request` that refuses a fact binding or a condition, for example `facts.amount.path` or `config.rules[0].when[1].fact`: the member of the request body the deployment cannot enforce, as a dotted and bracketed path into the body as sent, for example `subjects[0].type`, `config.mode`, `subject`, on `POST /v1/policies/simulate` `policies[2].subjects[0].type`, or on `proposal_refused` `action.arguments.policies[1].policy.targets.tools[0]`. Keys are the member names as sent; an index is a decimal integer; the first segment is a top-level member of the request body. `detail` stays human prose. A client reads `member`, and falls back to `detail` when a rev 12 deployment omits it.\n",
            min_length=1,
            pattern="^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*|\\[[0-9]+\\])*$",
        ),
    ] = None
    code: Annotated[
        str | None,
        Field(
            description="Only on `proposal_refused` (rev 14), and always present on it: why the proposal was refused. The documented values are `not_a_user`, `shape`, `unknown_agent`, `principal_bound`, `tool_ref_in_use`, `target_unknown`, `baseline_exists`, `tightening_looser` and, rev 18, `not_entitled` (see `PolicySetProposal`). A client treats a well-formed value it does not know as a plain refusal; a client that matches on `type` keeps working.\n",
            pattern="^[a-z][a-z0-9_]{0,63}$",
        ),
    ] = None


class Deployment(StrEnum):
    HOSTED = "hosted"
    EDGE = "edge"


class Meta(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    request_id: str
    deployment: Deployment
    cursor: str | None = None
    next: Annotated[
        str | None,
        Field(description="Pass as `cursor` for the next page; null on the last page.\n"),
    ] = None


class Timestamp(RootModel[AwareDatetime]):
    root: AwareDatetime


class Digest(RootModel[str]):
    root: Annotated[str, Field(description="Lowercase hex SHA-256.\n", pattern="^[0-9a-f]{64}$")]


class SideEffectLevel(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXTERNAL = "external"
    ADMIN = "admin"


class DecisionValue(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"
    DEFER = "defer"


class ObligationKind(StrEnum):
    TOOL_INVOCATION = "tool_invocation"
    SPENDING = "spending"


class Resolution(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="How an approval was resolved. Open-ended: the documented values are `approved`, `rejected` and `escalated`, and a client treats any other value as a resolution it does not act on. Known values: approved | rejected | escalated."
        ),
    ]


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    WITHDRAWN = "withdrawn"


class PrincipalKind(StrEnum):
    USER = "user"
    AGENT = "agent"
    SERVICE = "service"
    GROUP = "group"
    ROLE = "role"


class PrincipalRef(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[str, Field(min_length=1)]
    kind: PrincipalKind


class NamedPrincipalRef(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[str, Field(min_length=1)]
    kind: PrincipalKind
    display_name: Annotated[
        str | None,
        Field(
            description="The name the deployment knows the principal by. Optional: absent when the deployment cannot name the principal, never the id repeated and never null (see Who is named on an approval).\n",
            min_length=1,
        ),
    ] = None


class PolicyRef(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[str, Field(min_length=1)]
    version: Annotated[int, Field(ge=0)]


class DecisionPolicy(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[str, Field(min_length=1)]
    version: Annotated[int, Field(ge=0)]
    side_effect_level: SideEffectLevel


class ActorHint(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    agent_id: Annotated[
        str | None,
        Field(
            description="A display hint, never identity (rev 13). For a caller with no bound agent, `Approval.agent` reflects this client-supplied value, which the deployment has not verified.\n",
            min_length=1,
        ),
    ] = None
    run_id: Annotated[str | None, Field(min_length=1)] = None


class Action1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1)]
    method: Annotated[str | None, Field(min_length=1)] = None
    arg_digest: Digest
    arguments: dict[str, Any] | None = None


class Action2(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1)]
    method: Annotated[str | None, Field(min_length=1)] = None
    arg_digest: Digest | None = None
    arguments: dict[str, Any]


class Action(RootModel[Action1 | Action2]):
    root: Annotated[
        Action1 | Action2,
        Field(
            description="What is about to run. Exactly one of `arg_digest` (the digest of the arguments as sent) or `arguments` (the arguments themselves, which the server digests). Rev 16: the facts a policy's rules test are read from `arguments` through the tool's fact bindings (`Tool.facts`); a call that sends only `arg_digest` has no facts, so a rule that needs one is unevaluable and its policy asks.\n"
        ),
    ]


class Resource(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: str
    id: str
    properties: dict[str, Any] | None = None


class InvocationChannel(StrEnum):
    INTERACTIVE = "interactive"
    HEADLESS = "headless"
    WORKFLOW = "workflow"


class RecordContext(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    invocation_channel: InvocationChannel | None = None


class Kind(StrEnum):
    ADK = "adk"
    LANGGRAPH = "langgraph"
    VERCEL_AI = "vercel_ai"
    OPENAI_AGENTS = "openai_agents"
    WEBHOOK = "webhook"
    MCP_HELD = "mcp_held"
    AGT = "agt"
    CLAUDE_AGENT_SDK = "claude_agent_sdk"


class Delivery(StrEnum):
    PUSH = "push"
    PULL = "pull"
    HELD = "held"


class Continuation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: Kind
    delivery: Delivery
    correlation: dict[str, Any] | None = None
    callback_url: Annotated[str | None, Field(pattern="^https://")] = None
    expires_at: Annotated[
        Timestamp | None,
        Field(
            description="The continuation's own validity. It is separate from the approval's per-policy `expires_after`.\n"
        ),
    ] = None


class ApprovalHandle(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[
        str,
        Field(
            description="The approval id. It MUST be unguessable: not sequential and not derivable from the action, the scope or any other value a caller can compute. The 403 `not_eligible` that resolve, approve and deny answer to a service principal on kind alone shows that an approval with the id exists, and that exception relies on this (see Who sees an approval).\n"
        ),
    ]
    state: ApprovalState
    created: Annotated[
        bool,
        Field(description="True when this call opened the obligation, false when it matched an open one.\n"),
    ]
    created_at: Timestamp
    expires_at: AwareDatetime | None = None
    resume_token_will_issue: Annotated[
        bool,
        Field(
            description="True when the Resumption will carry a `resume_token` the caller must consume through `/consume`. When it is `false` the caller will receive no `resume_token`, has nothing to consume, and must not execute the action itself: the deployment executes the tool. A caller that holds a local function under a tool reference the deployment executes denies the call instead of running it, and withdraws the approval if its own decision opened it (`created`).\n"
        ),
    ]


class Condition(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: str
    resume_at: Timestamp | None = None
    ref: str | None = None


class HistoryEntry(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    resolution: Resolution
    by: NamedPrincipalRef
    at: Timestamp
    reason: Annotated[
        str | None,
        Field(
            description="Why, in the resolver's words. Rev 14: on a deployment-applied approval that the deployment refused to apply when it was approved, the entry has `resolution: rejected`, `by` the administrator whose approval was refused, and `reason` of the form `proposal_refused:<code>`, where `<code>` is a `Problem.code` of `proposal_refused` or `policy_conflict` (see Deployment-applied proposals).\n"
        ),
    ] = None


class ArgumentsState(StrEnum):
    SHOWN = "shown"
    NOT_ENABLED = "not_enabled"
    NOT_SENT = "not_sent"
    WITHHELD = "withheld"
    FINAL = "final"


class WaitingOn(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    count: Annotated[int, Field(ge=0)]
    principals: Annotated[list[NamedPrincipalRef] | None, Field(max_length=5)] = None


class OnDeny(StrEnum):
    RESUME = "resume"
    HALT = "halt"


class PriorRejections(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    count: Annotated[int, Field(ge=1)]
    last_at: Timestamp


class BlockedOn(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    reason: Annotated[
        str,
        Field(
            description="Why the call waits. `credential_link_required`: the principal needs a usable link to the registration. Open-ended: a client treats a value it does not know as a block it cannot clear itself.\n"
        ),
    ]
    connection_id: Annotated[str, Field(min_length=1)]


class ApprovalAgent(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    name: Annotated[
        str | None,
        Field(
            description="The agent's name (`Agent.name`), when the deployment can say. Absent otherwise.\n",
            min_length=1,
        ),
    ] = None
    parent: str | None = None


class Kind1(StrEnum):
    EXTERNAL = "external"
    GOVERNED = "governed"


class ApprovalRun(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    kind: Kind1


class ExcludeEnum(StrEnum):
    REQUESTER = "requester"


class Basis(StrEnum):
    LISTED = "listed"
    BREAK_GLASS = "break_glass"


class Approval1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    by: NamedPrincipalRef
    at: Timestamp
    basis: Annotated[
        Basis,
        Field(
            description="`listed`: the approver was eligible for the requirement itself. `break_glass`: an administrator of the organisation under the `approval_routing` setting.\n"
        ),
    ]


class Grant(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1)]


class ApprovalActionInput(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    name: Annotated[str, Field(min_length=1)]
    type: Annotated[
        str,
        Field(
            description="How the input is entered. Open-ended: the documented value is `text`, and a client does not offer an action that has an input of a type it does not know.\n"
        ),
    ]
    label: Annotated[
        str,
        Field(description="The deployment's wording for the input.\n", min_length=1),
    ]
    required: Annotated[
        bool,
        Field(description="Whether the action is refused without a value for this input.\n"),
    ]
    max_length: Annotated[
        int | None,
        Field(
            description="The most characters the deployment accepts for a `text` input.\n",
            ge=1,
        ),
    ] = None


class BlastRadius(StrEnum):
    ONE_RECORD = "one_record"
    MANY_RECORDS = "many_records"
    ORG_WIDE = "org_wide"


class PolicySetAssessment(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    side_effect_level: SideEffectLevel
    blast_radius: BlastRadius
    reversible: bool
    external_party: Annotated[
        bool,
        Field(description="Whether the tool acts on, or sends something to, a party outside the organisation.\n"),
    ]
    financial: bool


class Role(StrEnum):
    BASELINE = "baseline"
    TIGHTENING = "tightening"
    ROLE = "role"


class Agent1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[str, Field(min_length=1)]
    principal_id: Annotated[str | None, Field(min_length=1)] = None


class OwnerKind(StrEnum):
    PRINCIPAL = "principal"
    ORG = "org"


class ToolGrant(RootModel[str]):
    root: Annotated[str, Field(min_length=1)]


class ResolveResolution(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class ResolveRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    resolution: ResolveResolution
    reason: str | None = None
    input: Annotated[dict[str, Any] | None, Field(description="Typed human input. Opaque in v1.\n")] = None
    expected_action_digest: Annotated[
        Digest,
        Field(description="The digest the approver saw. A mismatch is 409 `approval_conflict`.\n"),
    ]


class ResolveBatchItem(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    approval_id: Annotated[str, Field(min_length=1)]
    resolution: ResolveResolution
    reason: str | None = None
    input: Annotated[dict[str, Any] | None, Field(description="Typed human input. Opaque in v1.\n")] = None
    expected_action_digest: Annotated[
        Digest,
        Field(description="The digest the approver saw. A mismatch is 409 `approval_conflict` for this element.\n"),
    ]


class ResolveBatchRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    items: Annotated[list[ResolveBatchItem], Field(max_length=100, min_length=1)]


class AliasResolveRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    reason: str | None = None
    expected_action_digest: Digest


class Resumption(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    approval_id: str
    action_id: Annotated[str, Field(description="An opaque server id for the action.\n")]
    tool_ref: str
    obligation_kind: ObligationKind
    resolution: Resolution
    action_digest: Digest
    approver: PrincipalRef
    resolved_at: Timestamp
    expires_at: Timestamp
    policy: PolicyRef | None = None
    resume_token: Annotated[
        str | None,
        Field(
            description="Present if and only if the caller consumes through `/consume`. Never given to an approving browser.\n"
        ),
    ] = None
    continuation: Annotated[
        Continuation,
        Field(
            description="The continuation the approval was opened with, echoed as the same JSON value, not the same bytes: member order and insignificant whitespace are not preserved and carry no meaning. The signature covers the JCS form of the object, which does not depend on member order.\n"
        ),
    ]
    signature: Annotated[str, Field(description="The JWS compact serialization.\n")]


class ConsumeRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    resume_token: Annotated[str, Field(min_length=1)]
    action: Annotated[Action, Field(description="The action as the runtime is about to run it.\n")]


class ConsumeResult(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    approval_id: str
    state: Literal["consumed"]
    consumed_at: Timestamp
    tool_ref: str
    action_digest: Digest


class ContinuationTestRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    continuation: Continuation


class Problem1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    field: str
    message: str


class ContinuationTestResult(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    valid: bool
    reachable: Annotated[bool | None, Field(description="Set for `push`, after a signed challenge.\n")] = None
    problems: list[Problem1] | None = None


class Status(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class RecordOutcome(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    status: Status
    summary: str | None = None
    error: str | None = None


class Attestation(StrEnum):
    OBSERVED = "observed"
    ASSERTED = "asserted"


class Reason(StrEnum):
    NOT_CONSUMED = "not_consumed"
    ALREADY_LINKED = "already_linked"
    NOT_FOUND = "not_found"


class ApprovalLink(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    linked: bool
    reason: Reason | None = None


class Degraded(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    reason: Annotated[
        str,
        Field(
            examples=[
                "timeout",
                "unreachable",
                "http_error",
                "no_token",
                "internal_error",
            ],
            pattern="^[a-z][a-z0-9_]{0,63}$",
        ),
    ]
    status: Annotated[int | None, Field(ge=400, le=599)] = None
    request_id: Annotated[str | None, Field(max_length=128, min_length=1)] = None


class RecordCreate(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1)]
    actor: ActorHint | None = None
    policy: Annotated[
        PolicyRef | None,
        Field(
            description="The policy that matched. Omit it when no policy matched explicitly and the default applied; when present, `id` and `version` are both required.\n"
        ),
    ] = None
    decision: DecisionValue
    approval_id: Annotated[
        str | None,
        Field(description="Links the outcome to the approval it followed.\n"),
    ] = None
    outcome: RecordOutcome | None = None
    prompt_id: str | None = None
    context: Annotated[
        RecordContext | None,
        Field(
            description="The invocation channel, the same enum and meaning as `context.invocation_channel` on the `/decisions` request; `call_id` and `group_id` are not accepted. `tool_use_id`, `source` and `side_effect_level` are deliberately not accepted: a deployment derives them, and a caller can never lower a level.\n"
        ),
    ] = None
    enforced: Annotated[
        bool | None,
        Field(
            description="`true` when absent. `false` means the decision was observed, not enforced, as on the decision object. On a degraded record it says whether the caller enforced the fallback.\n"
        ),
    ] = None
    degraded: Annotated[
        Degraded | None,
        Field(
            description="Set when the caller could not obtain a decision and went on under a fallback. `decision` is then the fallback the caller applied, `policy` must be absent (400 `invalid_request` otherwise), and `enforced` says whether the caller enforced that fallback. `side_effect_level` and everything else the deployment derives stay server-side.\n"
        ),
    ] = None


class RecordBatchRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    records: Annotated[list[RecordCreate], Field(max_length=100, min_length=1)]


class AgtEvent(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    event_type: str
    agent_id: str
    tool_name: str
    timestamp: Timestamp
    decision: str | None = None
    result: str | None = None


class ChainLink(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str | None
    reason: Annotated[str | None, Field(description="Why the link is null.\n")]


class RecordChain(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    prompt: ChainLink
    action: ChainLink
    decision: ChainLink
    approval: ChainLink
    outcome: ChainLink


class Checkpoint(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    created_at: Timestamp
    record_count: Annotated[int, Field(ge=0)]


class Verification(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    verified: bool
    checkpoint_id: str | None = None
    checked_at: Timestamp


class State(StrEnum):
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"


class EvidenceExport(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    state: State
    created_at: Timestamp


class PolicySource(StrEnum):
    AUTHORED = "authored"
    SUGGESTED = "suggested"
    IMPORTED = "imported"


class PolicyFormat(StrEnum):
    AGT = "agt"
    CEDAR = "cedar"


class PolicyKind(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="What a policy governs (rev 10). Open-ended: the documented kinds are `tool_invocation` (whether a call to a tool is allowed, asked or denied), `spending` (provisional) and `duplicate_requests` (what happens to an identical call after a resolver rejected it) and, since rev 16, `approval_routing` (the organisation's setting for who may satisfy an approval's requirements, see `ApprovalRoutingConfig`). A client treats a kind it does not know as a policy it cannot evaluate, never as a decision, and treats that policy's `config` as opaque. Known values: tool_invocation | spending | duplicate_requests | approval_routing."
        ),
    ]


class PolicyState(StrEnum):
    DRAFT = "draft"
    PUBLISHED = "published"


class PolicyMode(StrEnum):
    ALWAYS_ALLOW = "always_allow"
    ASK = "ask"
    ESCALATE = "escalate"
    DENY = "deny"
    NOT_GRANTED = "not_granted"


class FactName(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="Rev 16: the name of a fact a tool declares (`Tool.facts`) and a condition names (`PolicyCondition.fact`).\n",
            pattern="^[a-z][a-z0-9_]{0,62}$",
        ),
    ]


class Type(StrEnum):
    NUMBER = "number"
    STRING = "string"
    BOOLEAN = "boolean"
    COUNT = "count"


class FactBinding(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    path: Annotated[
        str,
        Field(
            description="Where the value is, from the root of the arguments: one or more segments, each `.key` (a member; `key` starts with a letter or `_` and holds letters, digits, `_` and `-`) or `[N]` (the element at the non-negative index `N` of an array). For example `.amount`, `.target.env`, `.lines[0].price`. A wildcard (`[*]`) or a recursive descent (`..key`) selects a set, not one value, and is refused with 400 `invalid_request` naming the binding in `member`.\n",
            max_length=512,
            pattern="^(\\.[A-Za-z_][A-Za-z0-9_-]*|\\[[0-9]+\\])+$",
        ),
    ]
    type: Type
    description: Annotated[str | None, Field(max_length=500)] = None


class ToolFacts(RootModel[dict[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")], FactBinding]]):
    root: Annotated[
        dict[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,62}$")], FactBinding],
        Field(
            description="Rev 16: the facts a tool declares, by name: at most 32. A policy's conditions name them (see `ToolInvocationConfig`). Served under the feature `tools.facts`; a deployment that does not list it refuses a write that carries `facts` with 422 `unsupported_policy_form` naming `facts`.\n",
            max_length=32,
        ),
    ]


class Op(StrEnum):
    EQ = "eq"
    NE = "ne"
    IN = "in"
    NOT_IN = "not_in"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    EXISTS = "exists"


class PolicyCondition(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    fact: FactName
    op: Op
    value: Annotated[
        Any | None,
        Field(description="What the fact is tested against; its form depends on `op` (see above).\n"),
    ] = None


class PolicyConditions(RootModel[list[PolicyCondition]]):
    root: Annotated[
        list[PolicyCondition],
        Field(
            description="Rev 16: one to eight conditions, all of which must hold (they are ANDed). An alternative is a separate rule.\n",
            max_length=8,
            min_length=1,
        ),
    ]


class Then(StrEnum):
    ALWAYS_ALLOW = "always_allow"
    ASK = "ask"
    DENY = "deny"


class PolicyApprover1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    role: Annotated[str, Field(min_length=1)]
    when: PolicyConditions | None = None


class PolicyApprover2(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    user: Annotated[str, Field(min_length=1)]
    when: PolicyConditions | None = None


class PolicyApprover(RootModel[PolicyApprover1 | PolicyApprover2]):
    root: Annotated[
        PolicyApprover1 | PolicyApprover2,
        Field(
            description="Rev 16: one entry of who may satisfy a requirement: every holder of a role (`role`, its bare key, as a role subject's id) or one user (`user`, the principal id). With `when`, the entry is in force for a call only when every condition holds; a condition that is false or unevaluable leaves it out.\n"
        ),
    ]


class ApproverRef1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    role: Annotated[str, Field(min_length=1)]


class ApproverRef2(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    user: Annotated[str, Field(min_length=1)]


class ApproverRef(RootModel[ApproverRef1 | ApproverRef2]):
    root: Annotated[
        ApproverRef1 | ApproverRef2,
        Field(
            description="Rev 16: an approver entry of a requirement, as it was in force when the approval was opened: a role by its bare key, or a user by principal id.\n"
        ),
    ]


class ApprovalRoutingConfig(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    org_admin_break_glass: Annotated[
        bool,
        Field(
            description="`true`: an administrator of the organisation may satisfy every unmet requirement of an approval in one approve (`basis: break_glass`), except a requirement whose `exclude` excludes them. `false`: an administrator satisfies only the requirements that list them, and those with no approver entries in force.\n"
        ),
    ]


class Limit(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    amount: float
    currency: str


class SpendingConfig(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    limit: Limit


class AfterRejection(StrEnum):
    DENY = "deny"
    ASK_AGAIN = "ask_again"


class DuplicateRequestsConfig(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    after_rejection: Annotated[
        AfterRejection,
        Field(
            description="`deny`: an identical call within the window of a rejection is answered `deny` with reason `rejected_duplicate` and opens nothing. `ask_again`: it opens a fresh approval carrying `prior_rejections`, until the count of rejections exceeds `max_reasks`.\n"
        ),
    ]
    window_seconds: Annotated[
        int | None,
        Field(
            description="How long after a rejection the rule applies, in seconds: a rejection counts while its `resolved_at` lies within this many seconds of the call. Absent means 86 400 (24 hours).\n",
            ge=60,
            le=2592000,
        ),
    ] = 86400
    max_reasks: Annotated[
        int | None,
        Field(
            description="Only with `ask_again`: how many resolver rejections of an identical call are each followed by a re-ask. With the count being the resolver's rejections of the identity within the window since its last consumed approval, a call whose count exceeds `max_reasks` is answered as under `deny` (`max_reasks: 1`: after the first rejection the call is asked again, after the second it is denied). It bounds rejections, not re-asks: a re-ask that is withdrawn or expires is not a rejection and does not count. Absent means no limit.\n",
            ge=1,
        ),
    ] = None


class PolicySubjectType(StrEnum):
    USER = "user"
    AGENT = "agent"
    SERVICE = "service"
    GROUP = "group"
    ROLE = "role"
    ORGANIZATION = "organization"


class PolicySubject1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: PrincipalKind
    id: str


class PolicySubject2(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: Literal["organization"]


class PolicySubject(RootModel[PolicySubject1 | PolicySubject2]):
    root: Annotated[
        PolicySubject1 | PolicySubject2,
        Field(
            description="Who a policy applies to: a principal by kind and id, or (rev 10) the organisation itself, `{ type: organization }`, with no id (it is the token's organisation). A role subject's id is the bare role key (for example `member`, or the reserved role `everyone` (rev 13), which every caller holds); a deployment maps it to its own form. Tools are never subjects: a policy names the tools it governs in `targets`.\n"
        ),
    ]


class Tool1(RootModel[str]):
    root: Annotated[str, Field(min_length=1)]


class Tools(RootModel[list[Tool1]]):
    root: Annotated[list[Tool1], Field(max_length=100, min_length=1)]


class PolicyTargets(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tools: Literal["all"] | Tools


class PolicyOrigin(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    format: PolicyFormat
    digest: Digest


class UnenforcedTarget(RootModel[str]):
    root: Annotated[str, Field(min_length=1)]


class Rule(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    index: Annotated[int, Field(ge=0)]
    then: Then


class Policy1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: PolicyKind
    id: Annotated[
        str | None,
        Field(
            description="The policy; null for a default of the deployment, or for a proposed body (rev 13).\n",
            min_length=1,
        ),
    ]
    version: Annotated[
        int | None,
        Field(
            description="The version considered (the draft, or the version simulated); null for a default of the deployment, or for a proposed body (rev 13).\n",
            ge=0,
        ),
    ]
    proposed_index: Annotated[
        int | None,
        Field(
            description="Rev 13: on an entry that comes from a proposed body of `POST /v1/policies/simulate`, the index of that body in the request's `policies`. A default of the deployment, which also has a null `id` and `version`, carries `source` and never `proposed_index`.\n",
            ge=0,
        ),
    ] = None
    result: Annotated[
        str,
        Field(
            description="What the entry gave: a mode for a `tool_invocation` policy; for a `duplicate_requests` policy `none` (no rejection applies), `deny` or `ask_again`.\n",
            min_length=1,
        ),
    ]
    subject: Annotated[
        PolicySubject | None,
        Field(description="The subject of the policy that matched the call.\n"),
    ] = None
    source: Annotated[
        str | None,
        Field(
            description="Present on a default: which one, for example `default` or `deployment_applied`. It is a value here and never a role: the reserved role is `everyone`. Absent on an entry from a stored policy or a proposed body; an entry is a default or a proposed body, never both.\n",
            min_length=1,
        ),
    ] = None
    contributed: Annotated[
        bool | None,
        Field(
            description="Rev 11: true on every entry the deployment used to reach `composed`, and false or absent on one it did not. Under `policies.tightest_wins` it is every entry whose result gives the composed decision: when that is a step-up, every approval-requiring entry, each of which contributes a requirement that must be met. An entry a tighter one overruled (an `always_allow` beside a `deny`) did not contribute. It says which entries determined the outcome, not an order among them. A deployment that does not implement rev 11 omits it.\n"
        ),
    ] = None
    rule: Annotated[
        Rule | None,
        Field(
            description="Rev 16: on a `tool_invocation` entry whose result a rule of the policy gave, that rule: its index in the policy's `rules` and its `then`. Absent when no rule matched (the result is the policy's `mode`), when a missing fact stopped the walk (see `missing_facts`), and on a deployment that does not list `policies.rules`.\n"
        ),
    ] = None
    missing_facts: Annotated[
        list[FactName] | None,
        Field(
            description="Rev 16: on a `tool_invocation` entry whose rules could not be evaluated, the facts the rule that stopped the walk needed and the call did not supply; the entry's `result` is then `ask`. A simulation whose `action` carries only `arg_digest` supplies no fact. Absent otherwise.\n",
            min_length=1,
        ),
    ] = None


class Composed(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    decision: DecisionValue
    reason: str | None = None


class ConsideredPolicies(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    policies: list[Policy1]
    composed: Composed


class SimulateResult(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    decision: DecisionValue
    reason: Annotated[
        str | None,
        Field(description="For example `not_granted`, `unknown_tool`, `rejected_duplicate`.\n"),
    ] = None
    action_digest: Annotated[
        Digest,
        Field(description="The argument digest the server computed for the action as received.\n"),
    ]
    policy: Annotated[
        DecisionPolicy | None,
        Field(
            description="The policy that decided; absent when the default applied. Where several policies contributed to the decision (rev 11; see `policies.tightest_wins` on `Capabilities.features`), it names one of the entries that contributed, the deployment's choice: the `considered` of a simulation lists the set.\n"
        ),
    ] = None
    approval: ApprovalHandle | None = None
    enforced: bool
    would_be: DecisionValue | None = None
    condition: Condition | None = None
    rejected_approval_id: Annotated[
        str | None,
        Field(
            description="Only on a `deny` with reason `rejected_duplicate`, as on `Decision`.\n",
            min_length=1,
        ),
    ] = None
    missing_facts: Annotated[
        list[FactName] | None,
        Field(
            description="Rev 16: only on a `step_up`, as on `Decision`: the facts whose absence stopped the walk of a contributing policy.\n",
            min_length=1,
        ),
    ] = None
    considered: ConsideredPolicies | None = None


class UnsupportedItem(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    path: str
    reason: str


class PolicyImportReport(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    applied: list[PolicyRef]
    unsupported: list[UnsupportedItem]


class Kind2(StrEnum):
    PRINCIPAL = "principal"
    ORG = "org"


class Owner(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: Kind2
    id: str


class Transport(StrEnum):
    MCP = "mcp"
    A2A = "a2a"


class StatusDetail(StrEnum):
    UNREACHABLE = "unreachable"
    CREDENTIAL_REJECTED = "credential_rejected"
    INTROSPECTION_FAILED = "introspection_failed"


class AuthKind(StrEnum):
    NONE = "none"
    BEARER = "bearer"
    OAUTH = "oauth"


class ConnectionLink(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    status: Annotated[
        str,
        Field(
            description="`linked`: the link holds a credential the deployment can use. `pending_authorization`: an OAuth link waiting for the caller to authorize it (`POST /v1/connections/{id}/authorize`). `degraded`: the deployment's last use of it failed. `none`: the caller has no link. Open-ended: a client treats a value it does not know as a link it cannot use. Known values: linked | pending_authorization | degraded | none."
        ),
    ]
    consent: Annotated[
        str,
        Field(
            description="`given`: the caller consents to the use of the link. `revoked`: it no longer does, and the deployment does not use the link (the credential is kept). `none`: there is no link. Open-ended: a client treats a value it does not know as consent not given. Known values: given | revoked | none."
        ),
    ]
    linked_at: Annotated[
        Timestamp | None,
        Field(description="When the link last came to hold a credential.\n"),
    ] = None


class ConnectionLinkRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    consent: Annotated[
        Literal[True],
        Field(description="The caller's consent to the use of its own link. Required, and only `true`.\n"),
    ]
    token: Annotated[
        str | None,
        Field(
            description="For `auth_kind: bearer`: the credential, required on the first link and replacing the stored one when sent again. Never returned. Refused for `auth_kind: oauth`.\n",
            min_length=1,
        ),
    ] = None


class ConnectionAuthorizeRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    return_to: Annotated[
        str,
        Field(
            description="Where the browser returns after consent: on an origin the deployment admits for browser modules. The deployment keeps `return_to`'s own query and adds the `nc_*` parameters to it.\n"
        ),
    ]


class ConnectionAuthorizeResult(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    authorization_url: Annotated[str, Field(description="Where to send the browser. Good for one use.\n")]
    expires_at: Timestamp


class ConnectionAuth1(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: Literal["none"]


class ConnectionAuth2(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: Literal["bearer"]


class Scope(RootModel[str]):
    root: Annotated[str, Field(min_length=1)]


class ConnectionAuth3(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: Literal["oauth"]
    scopes: list[Scope] | None = None
    issuer: str | None = None
    client_id: Annotated[str | None, Field(min_length=1)] = None


class ConnectionAuth(RootModel[ConnectionAuth1 | ConnectionAuth2 | ConnectionAuth3]):
    root: Annotated[
        ConnectionAuth1 | ConnectionAuth2 | ConnectionAuth3,
        Field(
            description="How a tool server authenticates callers (rev 11): `none`, `bearer` or `oauth`, which may name the `scopes` to ask for and the authorization server's `issuer` and the deployment's `client_id` there. It never carries a credential: an organisation credential is `org_credential`, and a user's is their link.\n"
        ),
    ]


class OrgCredential(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    token: Annotated[str, Field(min_length=1)]


class CredentialTier(StrEnum):
    ORG_SHARED = "org_shared"
    PER_USER = "per_user"


class ConnectionWrite(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    name: Annotated[str, Field(min_length=1)]
    url: Annotated[
        str,
        Field(
            description="The server's URL, which fixes the identity of its tools (rev 11). It carries no credential: a URL with userinfo is 400 `invalid_request`. It is shown to every principal who sees the registration.\n"
        ),
    ]
    transport: Transport
    owner_kind: Annotated[
        OwnerKind | None,
        Field(description="Whose connection this is. The owner id is the token's.\n"),
    ] = OwnerKind.PRINCIPAL
    auth: Annotated[
        ConnectionAuth | None,
        Field(description="How the server authenticates callers (rev 11). Absent means `{ kind: none }`.\n"),
    ] = None
    credential_tier: Annotated[
        CredentialTier | None,
        Field(
            description="Rev 11, administrator only, fixed at create: see `POST /v1/connections`. Absent, `per_user` where the deployment advertises `connections.user_links`, else `org_shared`.\n"
        ),
    ] = None
    org_credential: Annotated[
        OrgCredential | None,
        Field(
            description="Rev 11, administrator only: legal only with `credential_tier: org_shared` and `auth.kind: bearer`, which needs it.\n"
        ),
    ] = None


class ConnectionPatch(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    name: Annotated[str | None, Field(min_length=1)] = None
    org_credential: Annotated[
        OrgCredential | None,
        Field(
            description="Rev 11: rotates the organisation credential of an `org_shared` registration with `auth.kind: bearer`. Administrator only.\n"
        ),
    ] = None
    url: Annotated[
        str | None,
        Field(
            description="Refused with 400 `invalid_request` (rev 11): a connection's URL is the identity of its tools.\n"
        ),
    ] = None


class ConnectionRefreshResult(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_count: Annotated[int, Field(description="The tools the server offers now.\n", ge=0)]
    added: Annotated[int, Field(description="Tools registered for the first time.\n", ge=0)]
    removed: Annotated[int, Field(description="Tools no longer offered, now `withdrawn`.\n", ge=0)]
    reactivated: Annotated[
        int,
        Field(
            description="Tools offered again after they were withdrawn, `active` under the same `tool_ref`.\n",
            ge=0,
        ),
    ]
    empty_upstream_suppressed: Annotated[
        bool | None,
        Field(
            description="True when the server offered no tool at all and the deployment kept the registered tools rather than withdraw every one.\n"
        ),
    ] = None


class Transport2(StrEnum):
    MCP = "mcp"
    A2A = "a2a"
    EXTERNAL = "external"


class Tool(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    tool_ref: Annotated[
        str,
        Field(
            description="A deployment-assigned stable reference (rev 11): clients compare it for equality and never parse it. A deployment keeps it stable while the tool's server identity is unchanged, across disconnect and reconnect.\n"
        ),
    ]
    connection_id: Annotated[
        str | None,
        Field(
            description="The connection the tool was registered from; a `withdrawn` tool keeps the one it was last registered from. Null for a tool registered through `POST /v1/tools`.\n"
        ),
    ] = None
    status: Annotated[
        str | None,
        Field(
            description="Rev 11: `active`, or `withdrawn` when its server no longer offers it or its connection was deleted. A decision for a `withdrawn` tool is `deny` with reason `unknown_tool`, and it stays in `GET /v1/tools`. Absent means `active`; a hosted deployment returns it on every tool. Open-ended: a client treats a value it does not know as not callable. Known values: active | withdrawn."
        ),
    ] = None
    description: str | None = None
    transport: Transport2
    input_schema: dict[str, Any] | None = None
    side_effect_level: SideEffectLevel
    data_routing: Annotated[
        str,
        Field(description="The orchestrator's data-routing value. Opaque to this contract.\n"),
    ]
    owner: Owner | None = None
    show_arguments_to_approvers: Annotated[
        bool | None,
        Field(
            description="Whether the people who decide an approval of this tool see the call's arguments (see Who sees the arguments of an approval). Absent means `false`.\n"
        ),
    ] = None
    facts: Annotated[
        ToolFacts | None,
        Field(
            description="Rev 16: the facts a call to this tool carries, each read from its arguments. Absent: the tool declares none. Set only by a deployment that lists the feature `tools.facts`.\n"
        ),
    ] = None


class ToolWrite(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1)]
    transport: Literal["external"]
    description: str | None = None
    input_schema: dict[str, Any]
    side_effect_level: SideEffectLevel
    owner_kind: OwnerKind | None = OwnerKind.PRINCIPAL
    show_arguments_to_approvers: Annotated[
        bool | None,
        Field(
            description="Show the call's arguments to the people who decide an approval of this tool. A deployment that does not serve approvals accepts the field and ignores it.\n"
        ),
    ] = False
    facts: Annotated[
        ToolFacts | None,
        Field(description="Rev 16: the facts the tool declares (see `Tool.facts`).\n"),
    ] = None


class ToolPatch(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    description: str | None = None
    side_effect_level: SideEffectLevel | None = None
    input_schema: dict[str, Any] | None = None
    show_arguments_to_approvers: bool | None = None
    facts: Annotated[
        ToolFacts | None,
        Field(
            description="Rev 16: replaces the tool's whole map of facts; `null` removes every fact. A fact a published policy's condition names may be removed: that fact then has no value, so a condition naming it is unevaluable (false under `exists`), with the consequences the evaluation in `ToolInvocationConfig` gives.\n"
        ),
    ] = None


class Principal(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    kind: PrincipalKind
    display_name: str


class Agent(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    name: str
    parent_id: str | None
    created_at: Timestamp
    principal_id: Annotated[
        str | None,
        Field(
            description="Rev 13: the service principal this agent is bound to (see Agent identity), or null when it is unbound. Optional on the wire so that a rev 12 deployment's agent still validates; a client treats an absent member as null.\n",
            min_length=1,
        ),
    ] = None


class AgentPrincipalWrite(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    principal_id: Annotated[
        str,
        Field(
            description="The id of a service principal of the organisation: the `id` that `Record.actor` carries on a record the service principal appended, and that `GET /v1/principals` lists it under. An id that names no service principal of the caller's organisation, a user or a principal of another organisation included, is 404 `not_found`.\n",
            min_length=1,
        ),
    ]


class AgentWrite(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    name: Annotated[str, Field(min_length=1)]
    parent_id: str | None = None


class Kind3(StrEnum):
    EXTERNAL = "external"
    GOVERNED = "governed"


class Run(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    kind: Kind3
    scope_id: Annotated[
        str,
        Field(
            description="The scope approvals under this run are deduplicated in. A delegated run has a fresh scope id, so it never shares an obligation with its delegator.\n"
        ),
    ]
    agent_id: Annotated[
        str | None,
        Field(
            description="The agent the run was created for, as `createRun` was given it. Like `actor.agent_id` it is a hint and never selects which policies apply to a call that names the run (rev 13): an agent's policies apply only through the service principal bound to the agent (see Agent identity).\n"
        ),
    ] = None
    created_at: Timestamp


class RunWrite(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: Annotated[Kind3, Field(description="`governed` is refused with 405.\n")]
    agent_id: Annotated[
        str | None,
        Field(
            description="An agent of the caller's organisation (a row of `/v1/agents`); any other id is 404 `not_found`.\n"
        ),
    ] = None


class WebhookEvent(StrEnum):
    APPROVAL_RESOLVED = "approval.resolved"
    RECORD_APPENDED = "record.appended"
    POLICY_PUBLISHED = "policy.published"


class WebhookWrite(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    url: Annotated[str, Field(pattern="^https://")]
    events: Annotated[list[WebhookEvent], Field(min_length=1)]


class Specversion(StrEnum):
    FIELD_1_0 = "1.0"


class Datacontenttype(StrEnum):
    APPLICATION_JSON = "application/json"


class WebhookResolution(RootModel[str]):
    root: Annotated[
        str,
        Field(
            description="Rev 12. The resolution an `approval.resolved` delivery reports. Open-ended: the documented values are `approved`, `rejected` and `escalated`, and a client treats any other value as a resolution it does not act on (fail closed). A deployment delivers only the documented values. Known values: approved | rejected | escalated."
        ),
    ]


class State1(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalResolvedData(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    approval_id: str
    state: State1
    resolution: WebhookResolution
    resolved_at: Timestamp
    tool_ref: str


class RecordAppendedData(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    record_id: str
    tool_ref: str
    decision: str
    ts: Timestamp


class PolicyPublishedData(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    policy_id: str
    kind: str
    version: Annotated[int, Field(ge=1)]
    published_at: Timestamp


class Origins(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    origins: list[str]


class Origin(RootModel[str]):
    root: Annotated[
        str,
        Field(pattern="^(https://[^/?#@*\\s]+|http://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?)$"),
    ]


class OriginsWrite(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    origins: Annotated[
        list[Origin],
        Field(
            description="Rev 12: each origin is exact, `scheme://host[:port]` as a browser sends it in `Origin`: no path, query, fragment, trailing slash, userinfo or wildcard; `https`, or `http` only for `localhost` and `127.0.0.1`. The host is lowercase and a default port (443 for `https`, 80 for `http`) is omitted. The `pattern` is a coarse filter only; the rule stated here governs, and a deployment refuses a non-canonical form the pattern lets through. One that is not exact is 400 `invalid_request`, naming it.\n",
            max_length=50,
        ),
    ]


class Limits(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    decisions_batch_max_items: Annotated[
        int | None,
        Field(
            description="The most items `POST /v1/decisions/batch` accepts.\n",
            ge=1,
            le=100,
        ),
    ] = None
    records_batch_max_items: Annotated[
        int | None,
        Field(
            description="The most items `POST /v1/records/batch` accepts.\n",
            ge=1,
            le=100,
        ),
    ] = None
    resolutions_batch_max_items: Annotated[
        int | None,
        Field(
            description="The most items `POST /v1/approvals/resolve/batch` accepts.\n",
            ge=1,
            le=100,
        ),
    ] = None
    approval_arguments_max_bytes: Annotated[
        int | None,
        Field(
            description="The most bytes of arguments (RFC 8785 canonical JSON) this deployment keeps for an approval of a tool that shows its arguments to approvers. Larger arguments are refused with 400 `invalid_request`, whose `detail` says so; absent means this deployment sets no bound it advertises.\n",
            ge=1,
        ),
    ] = None


class ContinuationDelivery(StrEnum):
    PUSH = "push"
    PULL = "pull"
    HELD = "held"


class ToolRegistration(StrEnum):
    ANY = "any"
    ADMINISTRATORS = "administrators"


class Who(StrEnum):
    ANY = "any"
    ADMINISTRATORS = "administrators"


class ConnectionRegistration(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    owner_kinds: Annotated[list[OwnerKind], Field(min_length=1)]
    who: Who


class ConnectionTransport(StrEnum):
    MCP = "mcp"
    A2A = "a2a"


class ConfigMember(RootModel[str]):
    root: Annotated[str, Field(min_length=1)]


class ToolInvocation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    modes: list[PolicyMode]
    subject_types: list[PolicySubjectType]
    targets_all: bool
    config_members: Annotated[
        list[ConfigMember],
        Field(
            description="The members of `ToolInvocationConfig` besides `mode` this deployment implements, for example `on_deny`, `expires_after` and `approver_groups`.\n"
        ),
    ]


class ApprovalRouting(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    config_members: Annotated[
        list[ConfigMember],
        Field(
            description="The members of `ApprovalRoutingConfig` this deployment implements, for example `org_admin_break_glass`.\n"
        ),
    ]


class PolicyForms(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_invocation: ToolInvocation | None = None
    approval_routing: Annotated[
        ApprovalRouting | None,
        Field(
            description="Rev 16: the deployment serves policies of kind `approval_routing` (organisation subject, every tool).\n"
        ),
    ] = None


class DeploymentAppliedItem(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1, pattern="^tool:noblecloak:")]
    arguments_schema_ref: Annotated[
        str,
        Field(
            description="The name of the schema in `components.schemas` that `action.arguments` of an approval for this reference must fit, for example `PolicySetProposal`.\n",
            min_length=1,
        ),
    ]


class Proposals(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    row_kinds: Annotated[
        list[str],
        Field(
            description="The values of `PolicySetEntry.role` this deployment accepts. Open-ended: a client treats a kind it does not know as one it does not send. Known values: baseline | tightening | role.\n",
            min_length=1,
        ),
    ]
    members: Annotated[
        list[str],
        Field(
            description="The optional members of `PolicySetProposal` beyond those of rev 14 that this deployment accepts, possibly none. Open-ended: a client treats a member it does not know as one it does not send. Known values: tool_grants.\n"
        ),
    ]


class Dpop(StrEnum):
    OFF = "off"
    OPTIONAL = "optional"
    REQUIRED = "required"


class Capabilities(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    deployment: Deployment
    entitlements: Annotated[
        list[str],
        Field(
            description="The entitlement keys the organisation holds; a route or a request member that needs one names it. Open-ended: a client treats a key it does not know as one it does not use. A route names its key in `x-noblecloak-entitlement` (or, for one value of a parameter, `x-noblecloak-entitlement-for-values`) and answers 403 `entitlement_required` without it; rev 18, a `role` row of a `PolicySetProposal` needs `policies.role_subjects` and is refused `proposal_refused` with `code` `not_entitled` without it. Known values: records.verify | evidence.export | policies.suggested | policies.role_subjects.\n"
        ),
    ]
    jwks_uri: str
    kids: list[str]
    resolutions: Annotated[
        list[str],
        Field(
            description="The resolutions this deployment can produce. Empty when it does not serve approvals. A resolution it does not serve, `escalated` where it has no escalation, is refused with 400 `invalid_request`.\n"
        ),
    ]
    features: Annotated[
        list[str],
        Field(
            description="The route families served here (every family except `approvals`, which `resolutions` advertises: `runs`, `webhooks`, `origins`, `policies`, `agents`, `principals`, `connections`, `records.checkpoints`, `records.chain`, `evidence`), the hosted-only features (`policies.author`, `policies.publish`, `policies.import_export`, `policies.retire` (rev 11: retiring a policy and discarding its draft), `connections.oauth` (rev 11: the OAuth authorize step of a connection), `connections.user_links` (rev 11: each user's own credential link to a `per_user` registration, with consent), `records.verify` and `evidence.export`) and the features a deployment of either kind may have. `approvals.rejected_duplicate` (rev 10) says the deployment applies the rejected-duplicate rule (see Terminal states free the identity), and a deployment that does not list it keeps the rev 9 behaviour, where a rejection frees the identity. `approvals.available_actions` (rev 15) says the deployment sets `Approval.available_actions` on the single read of a pending approval, and a deployment that does not list it never sets the member. `policies.tightest_wins` (rev 11) states how the deployment composes `tool_invocation` policies: across every entry that matched a call the tightest mode wins, `deny` over needs approval (`ask`, `escalate`) over `always_allow`, and `not_granted` composes as `deny` (provisional, as `not_granted` is); a mode is loosened only through an exemption the deployment defines. Its default is a fallback, listed in `considered` only when no policy of its kind matched. A decision's `policy` names one of the entries that contributed, the deployment's choice, and the `considered` of a simulation gives the set (`contributed`). A deployment that does not list `policies.tightest_wins` states no rule. Rev 16: `tools.facts` says the deployment reads the facts of a call through `Tool.facts`; `policies.rules` says it evaluates `ToolInvocationConfig.rules`, lists `rule` and `missing_facts` in `considered`, and sets `Decision.missing_facts`; `approvals.requirements` says it enforces `ToolInvocationConfig.approvers` and `exclude`, serves `approval_routing` policies, and sets `Approval.requirements`. A deployment that does not list one of them refuses its members (422 `unsupported_policy_form`) and never sets the members it serves, so it behaves as rev 15. An edge deployment omits the hosted-only features and the families that are hosted-only.\n"
        ),
    ]
    authzen_configuration: str
    limits: Annotated[
        Limits | None,
        Field(
            description="The limits of this deployment. For the three batch limits (`decisions_batch_max_items`, `records_batch_max_items`, `resolutions_batch_max_items`) 100 is the most any deployment accepts, and a member that is absent means 100. A batch above a limit and no larger than 100 is 400 `batch_too_large`; one above 100 is 400 `invalid_request`, the schema's `maxItems`, whatever the limit.\n"
        ),
    ] = None
    continuation_deliveries: Annotated[
        list[ContinuationDelivery] | None,
        Field(
            description="The continuation deliveries this deployment serves. Absent means all three. A continuation whose delivery is not listed is refused with 400 `invalid_continuation`, as the routes that take one say.\n"
        ),
    ] = None
    continuation_kinds: Annotated[
        list[str] | None,
        Field(
            description="Rev 17: the continuation kinds this deployment accepts. Absent means the seven kinds of rev 16 (`adk` … `agt`): a deployment that accepts `claude_agent_sdk` lists it. A kind not accepted is 400 `invalid_request`, as a kind outside the `Continuation.kind` enum is. Unlike `continuation_deliveries`, where absent means all three, absent here is the list before rev 17, because a deployment that predates rev 17 cannot advertise the member. Open-ended: a client treats a kind it does not know as one it does not send. Known values: adk | langgraph | vercel_ai | openai_agents | webhook | mcp_held | agt | claude_agent_sdk.\n",
            min_length=1,
        ),
    ] = None
    tool_registration: Annotated[
        ToolRegistration | None,
        Field(
            description="Who may register or change tools: `any` principal of the organisation, or only its `administrators`. Absent means `any`. Any other principal is 403 `forbidden`, whatever the body. The per-tool setting `show_arguments_to_approvers` has no member of its own: it is honoured whenever `resolutions` is non-empty.\n"
        ),
    ] = None
    connection_registration: Annotated[
        ConnectionRegistration | None,
        Field(
            description="Who may register a connection here (rev 11): the owner kinds it accepts, and whether `any` principal of the organisation or only its `administrators` may register. Absent means unrestricted. A refused owner kind, or a refused caller, is 403 `forbidden`. It governs registration only, never who may use a registration, and never who changes, refreshes or deletes one: an `org`-owned connection is changed by administrators only on every deployment (see `PATCH /v1/connections/{id}`).\n"
        ),
    ] = None
    connection_transports: Annotated[
        list[ConnectionTransport] | None,
        Field(
            description="The connection transports this deployment serves (rev 11). Absent means both. A create naming another is 400 `invalid_request`.\n",
            min_length=1,
        ),
    ] = None
    policy_forms: Annotated[
        PolicyForms | None,
        Field(
            description="The policy forms this deployment enforces (rev 11), by kind. For `tool_invocation`: the modes, the subject types, whether a policy may target every tool (`targets_all`), and the members of `ToolInvocationConfig` besides `mode` it implements (`config_members`; rev 16 adds `rules` under `policies.rules`, and `approvers` and `exclude` under `approvals.requirements`). For `approval_routing` (rev 16, under `approvals.requirements`): the members of `ApprovalRoutingConfig` it implements; the kind is not served where the entry is absent. An advertised form is never refused with 422 `unsupported_policy_form`; a form it does not list may be. Absent means the deployment does not say, and a refused form is learnt from the 422.\n"
        ),
    ] = None
    deployment_applied: Annotated[
        list[DeploymentAppliedItem] | None,
        Field(
            description="Rev 14: the deployment-applied references this deployment applies on approval (see Deployment-applied proposals). A reference that is not listed is answered 422 `approval_unroutable` when an approval is opened for it. Absent means none: a deployment that does not author and publish policies of its own lists none.\n"
        ),
    ] = None
    proposals: Annotated[
        Proposals | None,
        Field(
            description="Rev 18: what this deployment accepts in a `PolicySetProposal`, where it lists `tool:noblecloak:propose-policy-set` in `deployment_applied`. Absent means what a deployment of rev 14 to 17 accepts: `row_kinds` `baseline` and `tightening`, and no optional member. A row kind or an optional member the deployment does not list is refused `proposal_refused` with `code` `shape`.\n"
        ),
    ] = None
    self_approval_from_approver_surface: Annotated[
        bool | None,
        Field(
            description="Whether a person may resolve an obligation their own agent opened when the resolving token was issued to the deployment's approver surface (the approvals module's own client). `true`: such a token resolves it; the creating principal's own token, from any client but the approver surface, is never eligible, and a token issued to the approver surface may not open an obligation on any path (`POST /v1/approvals`, a `step_up` on `POST /v1/decisions` or its batch, or an AuthZEN evaluation: 403 `forbidden`; `allow` and `deny` decisions are still answered) and may not consume a Resumption (`POST /v1/approvals/{id}/consume`: 403 `forbidden`), so one such token cannot approve an obligation and spend it. `false`: the creating principal never resolves its own obligation, from any surface. Absent means `false`, the rev 6 behaviour. A scenario that depends on it runs only where the deployment advertises the matching value.\n"
        ),
    ] = None
    user_resolve_scope: Annotated[
        str | None,
        Field(
            description="The OAuth scope a user-track token must carry to resolve an approval: `POST /v1/approvals/{id}/resolve`, `/approve`, `/deny` and `POST /v1/approvals/resolve/batch` answer 403 `insufficient_scope` to a user's token that lacks it, and answer it before the body is validated, before the approval is looked up and before eligibility: an approval id that does not exist is still 403 `insufficient_scope`, and a missing scope is never reported as `not_found`, `invalid_request` or `not_eligible`. Every non-service principal (a user or an agent) is asked for it; a service principal never resolves and is not asked. Withdraw, consume and every read are not gated by it. Absent means the deployment requires no user scope to resolve (the rev 7 behaviour). A scenario that depends on it runs only where the deployment advertises the member.\n",
            min_length=1,
        ),
    ] = None
    dpop: Annotated[
        Dpop | None,
        Field(
            description="Whether this deployment verifies DPoP proofs. `off` (the default when the member is absent): it verifies none, so a token that carries `cnf.jkt` and the `Authorization: DPoP` scheme are 401 `dpop_unsupported` and only bearer tokens are accepted. `optional`: a proof-bound token is accepted with its proof and a bearer token is accepted without one. `required`: a bearer token without a proof is 401. The `dpop_unsupported` negatives run only against `off`; against a deployment that advertises `optional` or `required` the conformance suite cannot check that it really verifies proofs, so those scenarios are reported as unverified skips, which count against the exit code unless skips are allowed.\n"
        ),
    ] = None


class Jwk(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kty: Literal["EC"]
    crv: Literal["P-256"]
    x: str
    y: str
    kid: str
    alg: Literal["ES256"] | None = None
    use: Literal["sig"] | None = None


class Jwks(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    keys: list[Jwk]


class AuthzenSubject(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    type: str
    id: str
    properties: dict[str, Any] | None = None


class AuthzenAction(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    name: str
    properties: dict[str, Any] | None = None


class AuthzenEvaluationRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    subject: AuthzenSubject
    action: AuthzenAction
    resource: AuthzenSubject
    context: dict[str, Any] | None = None


class AuthzenConfiguration(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    policy_decision_point: str
    access_evaluation_endpoint: str
    access_evaluations_endpoint: str | None = None


class ApprovalHandleEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: ApprovalHandle
    meta: Meta


class ResumptionEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Resumption
    meta: Meta


class ConsumeEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: ConsumeResult
    meta: Meta


class ContinuationTestEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: ContinuationTestResult
    meta: Meta


class RecordChainEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: RecordChain
    meta: Meta


class CheckpointEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Checkpoint
    meta: Meta


class VerificationEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Verification
    meta: Meta


class ExportEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: EvidenceExport
    meta: Meta


class SimulateEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: SimulateResult
    meta: Meta


class PolicyImportEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: PolicyImportReport
    meta: Meta


class ConnectionAuthorizeEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: ConnectionAuthorizeResult
    meta: Meta


class ConnectionRefreshEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: ConnectionRefreshResult
    meta: Meta


class ToolEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Tool
    meta: Meta


class ToolListEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[Tool]
    meta: Meta


class PrincipalListEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[Principal]
    meta: Meta


class AgentEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Agent
    meta: Meta


class RunEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Run
    meta: Meta


class OriginsEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Origins
    meta: Meta


class CapabilitiesEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Capabilities
    meta: Meta


class DecisionContext(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    invocation_channel: InvocationChannel | None = None
    call_id: str | None = None
    group_id: str | None = None


class DecisionRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    actor: ActorHint | None = None
    action: Action
    resource: Resource | None = None
    context: DecisionContext | None = None
    continuation: Continuation | None = None
    expect_approval_id: Annotated[
        str | None,
        Field(description="A hint only, used to log a mismatch. This route never consumes.\n"),
    ] = None


class DecisionBatchRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    requests: Annotated[list[DecisionRequest], Field(max_length=100, min_length=1)]


class Decision(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    decision: DecisionValue
    reason: Annotated[
        str | None,
        Field(
            description="For example `not_granted`, `rate_limited`, `unknown_tool`, `approval_unroutable`, `rejected_duplicate`, `credential_link_required` (rev 11: a `deny` for a direct call by a caller with no usable credential link to the `per_user` registration of the tool, when no approval is opened).\n"
        ),
    ] = None
    action_digest: Annotated[
        Digest,
        Field(description="The argument digest the server computed for the action as received.\n"),
    ]
    policy: Annotated[
        DecisionPolicy | None,
        Field(
            description="The policy that decided; absent when the default applied. Where several policies contributed to the decision (rev 11; see `policies.tightest_wins` on `Capabilities.features`), it names one of the entries that contributed, the deployment's choice: the `considered` of a simulation lists the set.\n"
        ),
    ] = None
    approval: ApprovalHandle | None = None
    enforced: bool
    would_be: DecisionValue | None = None
    condition: Condition | None = None
    rejected_approval_id: Annotated[
        str | None,
        Field(
            description="Only on a `deny` with reason `rejected_duplicate` (rev 10): the most recent rejected approval, within the window, whose identity this call repeats, readable under the rules of Who sees an approval. Absent on every other decision.\n",
            min_length=1,
        ),
    ] = None
    missing_facts: Annotated[
        list[FactName] | None,
        Field(
            description="Rev 16: on a `step_up`, the facts with no value that stopped the rule walk of a policy that contributed to it (see the evaluation in `ToolInvocationConfig`), each once, in the order the policies and their rules name them. Absent when every contributing policy's result came from a rule that matched or from its `mode`, and on every other decision. Set only by a deployment that lists the feature `policies.rules`.\n",
            min_length=1,
        ),
    ] = None


class CreateApprovalRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    action: Action
    continuation: Continuation
    run_id: Annotated[str | None, Field(min_length=1)] = None
    resource: Resource | None = None
    context: DecisionContext | None = None


class ApprovalRequirement(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[str, Field(description="Stable within the approval.\n", min_length=1)]
    policies: Annotated[
        list[PolicyRef],
        Field(
            description="The policies that contributed the requirement, at the versions that decided.\n",
            min_length=1,
        ),
    ]
    approvers: Annotated[
        list[ApproverRef],
        Field(
            description="The approver entries in force when the approval was opened (the matching rule's `approvers` when it had them, else the policy's, keeping only the entries whose `when` held). Empty: the organisation's administrators.\n"
        ),
    ]
    exclude: list[ExcludeEnum]
    needed: Annotated[
        int,
        Field(
            description="How many eligible principals must approve to meet it. Always 1 in rev 16.\n",
            ge=1,
        ),
    ]
    met: bool
    approvals: Annotated[
        list[Approval1],
        Field(description="The approvals that count toward it, oldest first.\n"),
    ]


class Simulation(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1)]
    result: SimulateResult


class LooseningItem(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1)]
    from_: Annotated[PolicyMode, Field(alias="from")]
    to: PolicyMode
    subject: Annotated[
        PolicySubject | None,
        Field(
            description="Rev 18: the subject of the `role` row the entry is for, `{ type: role, id: <key> }`. Absent on the entry of a `baseline`, which is for every caller.\n"
        ),
    ] = None


class IneffectiveItem(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1)]
    subject: PolicySubject


class ApprovalPreview(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    simulations: Annotated[
        list[Simulation],
        Field(
            description="One entry for each tool that the proposal's policies govern, in the order the tools first appear in `policies`: the decision for a call to that tool, composed for the agent of the proposal, as a simulation as `{ type: agent, id: <agent.id> }` with every proposed body standing beside the policies in force and the proposal's tools registered. Once the agent is bound, the bound service principal holds those policies, besides its own `service` policies. Rev 18: for a proposal without `agent`, the simulation is as `{ type: role, id: everyone }`, the baseline every caller holds. A simulation as `everyone` or as the agent does not show what a `role` row does, since neither holds the role: `loosening` and `ineffective` report the `role` rows.\n"
        ),
    ]
    loosening: Annotated[
        list[LooseningItem],
        Field(
            description="One entry for each `baseline` policy of the proposal whose mode is looser than the mode the deployment's own default gives the tool (the mode of the `considered` entry with `source` `default` that a simulation lists when no policy of the kind matched; for a tool this proposal registers, the mode it would have once registered). Rev 18: and one entry, with `subject`, for each `role` row that loosens what a holder of its role gets for the tool: `from` is what tightest-wins composes for the role now, from the published `tool_invocation` policies it holds for the tool (of the role itself, of `everyone` and of the organisation) or, where there are none, the default; `to` is what it composes with the proposal's `baseline` for the tool and the row beside them. So a `role` row loosens only where no published policy the role holds governs the tool. `deny` is tighter than `ask` and `escalate`, which are tighter than `always_allow`. A row that keeps or tightens what it is compared with has no entry, so an empty list says that approving loosens nothing for any caller. A `tightening` never loosens: opening refuses one looser than what the agent gets without it (`tightening_looser`).\n"
        ),
    ]
    grants: Annotated[
        list[Grant] | None,
        Field(
            description="Rev 18: one entry for each reference of the proposal's `tool_grants`, in that order: the tools whose grant approving records for the service principal in `agent.principal_id`. Absent or empty when the proposal carries no `tool_grants`.\n"
        ),
    ] = None
    ineffective: Annotated[
        list[IneffectiveItem] | None,
        Field(
            description="Rev 18: one entry for each `role` row of the proposal whose mode is looser than the tightest mode a `tool_invocation` policy of the role `everyone` gives the same tool, counting the published policies and the proposal's own `baseline` rows. Under tightest-wins such a row changes nothing for the role while that policy of `everyone` stands. It is reported to the approver and refuses nothing. Absent or empty means no row of the proposal is shadowed this way.\n"
        ),
    ] = None


class ApprovalAction(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[
        str,
        Field(description="Names the action; unique within the list.\n", min_length=1),
    ]
    kind: Annotated[
        str,
        Field(
            description="What the action does. Open-ended: the documented value is `resolve`, and a client ignores an action whose kind it does not know.\n"
        ),
    ]
    resolution: Annotated[
        ResolveResolution | None,
        Field(
            description="The resolution the action sends to `POST /v1/approvals/{id}/resolve`. Present exactly when `kind` is `resolve`.\n"
        ),
    ] = None
    label: Annotated[
        str,
        Field(
            description="The deployment's wording for the action, for example the wording of a denial.\n",
            min_length=1,
        ),
    ]
    inputs: Annotated[
        list[ApprovalActionInput],
        Field(description="The inputs the action takes, possibly none.\n"),
    ]


class PolicySetProposalTool(ToolWrite):
    model_config = ConfigDict(
        extra="allow",
    )
    tool_ref: Annotated[str, Field(min_length=1, pattern="^ext:")]
    owner_kind: Literal["org"]


class Record(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    ts: Timestamp
    actor: PrincipalRef
    tool_ref: str
    policy: Annotated[
        PolicyRef | None,
        Field(
            description="The policy that matched. Absent when no policy matched explicitly and the default applied, as on the decision object; when present, `id` and `version` are both required and never null.\n"
        ),
    ] = None
    decision: DecisionValue
    approval_id: str | None = None
    approval_link: Annotated[
        ApprovalLink | None,
        Field(
            description="Whether the deployment linked this record to the approval named by `approval_id`. Present on the 201 of `POST /v1/records` (and of each element of `POST /v1/records/batch`) only when the request carried `approval_id`; absent on a read and on a record appended without one. The record is appended whether or not the link was made: a refused link is not an error and the status is 201 either way.\n"
        ),
    ] = None
    outcome: RecordOutcome | None = None
    prompt_id: str | None = None
    context: Annotated[
        RecordContext | None,
        Field(
            description="The context the caller supplied when it appended the record. Absent when none was supplied.\n"
        ),
    ] = None
    enforced: Annotated[
        bool | None,
        Field(
            description="`false` means the decision was observed, not enforced, as on the decision object. Echoed as supplied; absent means `true`.\n"
        ),
    ] = None
    degraded: Annotated[
        Degraded | None,
        Field(
            description="Present when the caller could not obtain a decision and applied a fallback: `decision` is that fallback and `policy` is absent. Absent, not null, on every other record. A reader tolerates a `reason` it does not know. A deployment returns the members `Degraded` defines (`reason`, `status`, `request_id`) and no others at v1, so one schema serves the request and the response.\n"
        ),
    ] = None
    attestation: Annotated[
        Attestation,
        Field(
            description="Derived by the server. Every record appended through `/v1` is `asserted`. `observed` is a valid value on a read, reserved for records the platform captured itself.\n"
        ),
    ]


class PolicyRule(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    when: PolicyConditions
    then: Then
    approvers: Annotated[list[PolicyApprover] | None, Field(max_length=32, min_length=1)] = None


class SimulateRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    draft_version: Annotated[int | None, Field(ge=0)] = None
    actor: ActorHint | None = None
    action: Action
    resource: Resource | None = None
    context: DecisionContext | None = None
    subject: Annotated[
        PolicySubject | None,
        Field(
            description="Simulate for a hypothetical holder of exactly this subject (rev 11; see `POST /v1/policies/{id}/simulate`). Administrators only. The caller remains the token's principal.\n"
        ),
    ] = None


class Connection(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    name: str
    url: str
    transport: Transport
    owner: Owner
    created_at: Timestamp
    status: Annotated[
        str | None,
        Field(
            description="The state of the registration (rev 11), never a user's credential. `connected`: the registration is in force (for `org_shared`, its organisation credential is too). `pending_authorization`: an `org_shared` registration with `auth_kind: oauth` waiting for an administrator's consent; never used for a `per_user` registration. `degraded`: the deployment's last check of it failed (`status_detail` says how). Open-ended: a client treats a value it does not know as not `connected`. Known values: connected | pending_authorization | degraded."
        ),
    ] = None
    status_detail: Annotated[
        StatusDetail | None,
        Field(
            description="Why the registration is `degraded` (rev 11): a code from this closed list, never text from the server. Absent otherwise.\n"
        ),
    ] = None
    last_verified_at: Annotated[
        AwareDatetime | None,
        Field(description="When the deployment last checked the registration (rev 11); null when it never has.\n"),
    ] = None
    auth_kind: Annotated[
        AuthKind | None,
        Field(
            description="How the server authenticates callers (rev 11; `ConnectionWrite.auth`). Never a credential.\n"
        ),
    ] = None
    credential_tier: Annotated[
        str | None,
        Field(
            description="Whose credential calls through the registration use (rev 11): `org_shared`, one organisation credential an administrator sets; `per_user`, each user's own link. Fixed at create. Open-ended: a client treats a value it does not know as a tier it cannot use. Known values: org_shared | per_user."
        ),
    ] = None
    my_link: Annotated[
        ConnectionLink | None,
        Field(
            description="The caller's own credential link to this registration, and nobody else's (rev 11). Present on every read of a `per_user` registration whose `auth_kind` is not `none`, by a deployment that advertises `connections.user_links`; absent otherwise. Never a credential.\n"
        ),
    ] = None


class Webhook(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    url: str
    events: list[WebhookEvent]
    state: Annotated[
        str | None,
        Field(
            description="Rev 12. Whether the webhook gets deliveries; absent means `active`. `disabled`: its deliveries failed continuously for 72 hours, and it gets none until it is deleted and created anew. A client treats a value it does not know as not `active`. Known values: active | disabled."
        ),
    ] = None
    created_at: Timestamp


class WebhookDelivery(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    specversion: Specversion
    id: str
    type: WebhookEvent
    source: Annotated[str, Field(description="The origin of the deployment's govern host.\n")]
    subject: Annotated[str, Field(description="The id of the resource the event is about.\n")]
    time: Timestamp
    datacontenttype: Datacontenttype
    data: Annotated[
        ApprovalResolvedData | RecordAppendedData | PolicyPublishedData,
        Field(
            description="The event data for `type`, and only for `type`: `approval.resolved` carries ApprovalResolvedData, `record.appended` RecordAppendedData, `policy.published` PolicyPublishedData. Thin, never carrying the resource's representation.\n"
        ),
    ]
    signature: str


class Context(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    noblecloak: Decision | None = None


class AuthzenEvaluationResponse(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    decision: bool
    context: Context | None = None


class DecisionEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Decision
    meta: Meta


class Data(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    decisions: list[Decision]


class DecisionBatchEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Data
    meta: Meta


class RecordEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Record
    meta: Meta


class RecordListEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[Record]
    meta: Meta


class RecordBatchEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[Record]
    meta: Meta


class ConnectionEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Connection
    meta: Meta


class ConnectionListEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[Connection]
    meta: Meta


class WebhookEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Webhook
    meta: Meta


class WebhookListEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[Webhook]
    meta: Meta


class Approval(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: Annotated[
        str,
        Field(
            description="The approval id. It MUST be unguessable: not sequential and not derivable from the action, the scope or any other value a caller can compute. The 403 `not_eligible` that resolve, approve and deny answer to a service principal on kind alone shows that an approval with the id exists, and that exception relies on this (see Who sees an approval).\n"
        ),
    ]
    state: ApprovalState
    resolution: Resolution | None = None
    tool_ref: str
    obligation_kind: ObligationKind
    action_digest: Digest
    arguments: Annotated[
        dict[str, Any] | None,
        Field(
            description="The arguments as the caller sent them (their digest is `action_digest`). Present only on `GET /v1/approvals/{id}`, and only when the tool has `show_arguments_to_approvers` on at the time of the read, the approval is not final and the reader is the principal that created it or one eligible to approve it; absent everywhere else, and then the digest is all a reader sees (see Who sees the arguments of an approval).\n"
        ),
    ] = None
    arguments_state: Annotated[
        ArgumentsState | None,
        Field(
            description="Why a read shows the arguments or not. Present on `GET /v1/approvals/{id}` and on each approval of `GET /v1/approvals`; a stream event may omit it, and a client then treats the state as unknown. `shown`: `arguments` is present (never on a list row, which carries no `arguments`; the state there says what the single read would show). `not_enabled`: the tool's `show_arguments_to_approvers` is off. `not_sent`: the approval holds no arguments, because the request that opened it carried only `arg_digest` or the setting was off then. `withheld`: the reader is neither the creator nor eligible to approve. `final`: the approval is in a final state. A reader who is neither the creator nor eligible to approve is told `final` for an approval in a final state and `withheld` otherwise, never `not_enabled`, `not_sent` or `shown`; the creator and an eligible approver are told the first of `final`, `not_enabled`, `not_sent`, `shown` that applies, never `withheld`. It discloses nothing of the arguments (see Who sees the arguments of an approval).\n"
        ),
    ] = None
    scope_id: str
    side_effect_level: SideEffectLevel
    policy: PolicyRef | None = None
    requester: Annotated[
        NamedPrincipalRef | None,
        Field(
            description="The principal that created the approval. Present on every representation to any reader who can see the approval (see Who is named on an approval).\n"
        ),
    ] = None
    waiting_on: Annotated[
        WaitingOn | None,
        Field(
            description="Who a pending approval waits on, to the principal that created it and to no one else, on `GET /v1/approvals/{id}` only: never a row of `GET /v1/approvals` or an event of the stream. `count` is the number of principals eligible to resolve the approval that the deployment knows of at the time of the read; it may be zero, may change between reads, and is not a promise that any of them has been notified. `principals` is at most five of them. Rev 16: on an approval that carries `requirements`, the principals counted are those eligible for at least one unmet requirement, never the creator. Absent on an approval that is not pending and for every other reader, and absent when the deployment cannot determine who is eligible (the read is still 200, never an error on that account). For a service-principal creator `principals` is omitted and only the count is given.\n"
        ),
    ] = None
    on_deny: Annotated[
        OnDeny | None,
        Field(
            description="What the requester's run does when the approval is denied, as the policy that matched stated it when the approval was created (rev 9): a snapshot of that policy's `on_deny`, so a later edit of the policy does not change an approval that already exists. It is the creator's alone, on every representation of the approval that the creator reads, and absent for every other reader. It is absent when no named policy matched (`policy` is absent), when the matching policy states none, and when the matching policy's mode is not `ask` or `escalate`, where `ToolInvocationConfig` makes `on_deny` illegal. A deployment that does not implement `on_deny` on its policies omits it from every approval, and a client then treats what a deny does as not stated, never as `resume` or `halt`.\n"
        ),
    ] = None
    prior_rejections: Annotated[
        PriorRejections | None,
        Field(
            description="Set when the approval was opened for an identity a resolver had already rejected, because the organisation's duplicate-requests policy says `ask_again` (rev 10; see Terminal states free the identity): `count` is the number of a resolver's rejections of this identity within the policy's window since its last consumed approval, and `last_at` is when the latest of them was resolved. Present on every representation of the approval (the single read, a row of the list, a stream event) to every reader who can see the approval, and absent on an approval opened for an identity with no such rejection. A deployment that does not advertise `approvals.rejected_duplicate` never sets it.\n"
        ),
    ] = None
    blocked_on: Annotated[
        BlockedOn | None,
        Field(
            description="Rev 11: the call would run through the deployment as a principal with no usable credential link (none, consent not `given`, or `degraded`) to the `per_user` registration `connection_id`. It is shown only to the principal the call would run as (the run's owner; on a direct call, the creator), on the single read and on a row of the list, and is absent for every other reader and on every stream event. An approval with `blocked_on` may still be resolved; the deployment does not execute the call or issue its resume token while it is present, and clears it once that principal's link is `linked` with `consent: given`. It follows that link on every read of a pending or approved approval: revoking consent sets it again. The way out is the link routes: `POST /v1/connections/{connection_id}/link`, then, for a registration whose `auth_kind` is `oauth`, `POST /v1/connections/{connection_id}/authorize`. A deployment that does not advertise `connections.user_links`, and so every edge deployment, never sets it.\n"
        ),
    ] = None
    agent: Annotated[
        ApprovalAgent | None,
        Field(
            description="The agent the approval names. For a caller bound to an agent it is that agent. For a caller with no bound agent it reflects the client's unverified `actor.agent_id` hint (rev 13): display only, and an approver must not treat it as identity.\n"
        ),
    ] = None
    run: ApprovalRun | None = None
    continuation_kind: str | None = None
    continuation: Annotated[
        Continuation | None,
        Field(
            description="The continuation as it was sent, echoed to the principal that created the approval and to no one else. It is echoed as the same JSON value, not the same bytes: the order of an object's members and insignificant whitespace are not preserved and carry no meaning, so a deployment that keeps JSON in a normalising store may return the members in another order.\n"
        ),
    ] = None
    created_at: Timestamp
    expires_at: AwareDatetime | None = None
    resolved_at: AwareDatetime | None = None
    approver: NamedPrincipalRef | None = None
    outcome_record_id: Annotated[
        str | None,
        Field(description="The record that reported what happened after consumption.\n"),
    ] = None
    resolution_history: list[HistoryEntry] | None = None
    preview: Annotated[
        ApprovalPreview | None,
        Field(
            description="Rev 14: what approving a deployment-applied approval would change, computed when it was opened. Present only on `GET /v1/approvals/{id}`, only while the approval is `pending`, and only to a reader who may approve it; absent on every other representation, for every other reader and on an approval of an ordinary tool. A rev 13 reader never needs it.\n"
        ),
    ] = None
    available_actions: Annotated[
        list[ApprovalAction] | None,
        Field(
            description="Rev 15: what the reader may do on this approval, with the deployment's wording and the inputs each action takes. Present only on `GET /v1/approvals/{id}`, only while the approval is `pending`, and only to a reader who may resolve it, and only on a deployment that lists the feature `approvals.available_actions`; absent on every other representation (a list row, a stream event) and for every other reader. The `resolution` of each `resolve` action is one of `Capabilities.resolutions`. On a deployment that does not list `approvals.available_actions`, absent means the deployment does not say, and a client derives approve and deny from `Capabilities.resolutions`. On a deployment that lists it, absent means no action for this reader, and a client derives none. Being listed is not authorisation: resolving still decides eligibility when it is called. A rev 14 reader never needs it.\n"
        ),
    ] = None
    requirements: Annotated[
        list[ApprovalRequirement] | None,
        Field(
            description="Rev 16: what must be met before the approval is approved, one entry per requirement. Each policy whose result asked and that contributed to the step-up that opened the approval (for one opened through `POST /v1/approvals`, the step-up a decision of the same call would give) contributes one requirement, and two policies whose approver entries in force and `exclude` are the same (an entry listed twice counts once) contribute one requirement between them, which lists both. Present on every representation of the approval to every reader who can see it, on a deployment that lists the feature `approvals.requirements`, and only there: a deployment that does not list it never sets the member. Where the feature is listed, an approval without the member has one requirement, satisfied as before rev 16.\n\nJoining: a decision or `POST /v1/approvals` whose call matches an open approval joins it (two requirements are the same when their approver entries and `exclude` are). A `pending` approval that lacks requirements the call sets gains them, unmet, and emits `approval.updated`, so a joined `pending` approval never carries fewer requirements than the call sets. An `approved` approval that has not been consumed is joined as it is: its requirements are the ones in force when it was approved, and a requirement the call sets later is not added to it and does not open another approval. An approval binds the decision it answered, the same reason `on_deny` and the organisation's break-glass setting are fixed when the approval opens, and there is one approval per call identity at a time.\n\nApprove: the approver satisfies every unmet requirement they are eligible for, so one person may satisfy several, and the approval is `approved` once every requirement is met. An approve that leaves a requirement unmet answers 200 with the approval still `pending`, no `resolution`, and the requirements it satisfied recording the approver; it emits `approval.updated`. Reject: any principal eligible for at least one unmet requirement rejects the approval, whatever has been met. An approve or reject by a principal eligible for no unmet requirement is 403 `not_eligible` while the approval is `pending`; once it is not, a principal eligible for any of its requirements is answered as before rev 16 (409 `already_resolved` for an approval already resolved). The rules on the creator (see Who may resolve, and `Capabilities.self_approval_from_approver_surface`) apply on top: a requirement whose `exclude` holds `requester` is never satisfied by the creator, from any surface. A rev 15 reader never needs it.\n"
        ),
    ] = None


class ResolveBatchResult(RootModel[Approval | Problem]):
    root: Annotated[
        Approval | Problem,
        Field(
            description="The outcome of one element: the `Approval` after resolution, or a problem document. A problem has `type` and no `id`; an approval has `id` and no `type`.\n"
        ),
    ]


class ToolInvocationConfig(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    mode: Annotated[
        PolicyMode,
        Field(description="The outcome when no rule matches; with no `rules`, the outcome. Required.\n"),
    ]
    on_deny: OnDeny | None = None
    expires_after: Annotated[str | None, Field(description="An ISO 8601 duration, for example PT1H.\n")] = None
    approver_groups: Annotated[
        list[str] | None,
        Field(
            description="Together these groups form one approval requirement, satisfied by any eligible member of any listed group (rev 11, D-A90): each approval-requiring policy that matches a call contributes one requirement, and every requirement must be met. The schema may grow per ADR-0049 §6c.4.\n"
        ),
    ] = None
    rules: Annotated[
        list[PolicyRule] | None,
        Field(
            description="Rev 16: rules over the facts of the call, evaluated in order; the first that matches gives the policy's result, and `mode` applies when none does (see the evaluation above). Served under the feature `policies.rules`.\n",
            max_length=32,
            min_length=1,
        ),
    ] = None
    approvers: Annotated[
        list[PolicyApprover] | None,
        Field(
            description="Rev 16: who may satisfy the requirement this policy contributes when its result asks: `mode` asks and no rule matched, or a rule whose `then` is `ask` matched and carries no `approvers` of its own. Not when a fact with no value stopped the walk (see the evaluation above). Each entry is a role or a user, and is in force for a call only while its own `when` holds. The deployment enforces it, unlike `approver_groups`, which it leaves as it was. Served under the feature `approvals.requirements`.\n",
            max_length=32,
            min_length=1,
        ),
    ] = None
    exclude: Annotated[
        list[ExcludeEnum] | None,
        Field(
            description="Rev 16: who may never satisfy this policy's requirement, whatever else makes them eligible. `requester`: the principal that opened the approval, including from the approver surface and as an organisation administrator under break-glass. Served under the feature `approvals.requirements`.\n",
            min_length=1,
        ),
    ] = None


class PolicyConfig(RootModel[ToolInvocationConfig | SpendingConfig | DuplicateRequestsConfig | ApprovalRoutingConfig]):
    root: Annotated[
        ToolInvocationConfig | SpendingConfig | DuplicateRequestsConfig | ApprovalRoutingConfig,
        Field(
            description="The configuration of a policy, by its kind (rev 10): `ToolInvocationConfig` for `tool_invocation`, `SpendingConfig` for `spending`, `DuplicateRequestsConfig` for `duplicate_requests` and (rev 16) `ApprovalRoutingConfig` for `approval_routing`. The schema accepts any of them; that a configuration fits its policy's `kind` is checked by the server, which answers a write whose `config` does not fit 400 `invalid_request`. A client treats the `config` of a kind it does not know as opaque.\n"
        ),
    ]


class PolicyWrite(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    kind: PolicyKind
    name: Annotated[
        str | None,
        Field(
            description="Absent on create, the deployment derives one.\n",
            max_length=200,
            min_length=1,
        ),
    ] = None
    description: Annotated[str | None, Field(max_length=2000)] = None
    subjects: Annotated[list[PolicySubject], Field(min_length=1)]
    targets: Annotated[PolicyTargets | None, Field(description="Absent means every tool.\n")] = None
    config: PolicyConfig
    origin: Annotated[
        PolicyOrigin | None,
        Field(
            description="Where this version comes from, when it was imported (rev 11). A create that carries it makes a policy whose `source` is `imported`. `source` is fixed at create, so a later write with or without `origin` never changes it; `origin` describes the version it was written with.\n"
        ),
    ] = None


class Policy(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    id: str
    version: Annotated[int, Field(ge=0)]
    source: PolicySource
    kind: PolicyKind
    name: Annotated[str | None, Field(max_length=200, min_length=1)] = None
    description: Annotated[str | None, Field(max_length=2000)] = None
    state: PolicyState | None = None
    subjects: Annotated[list[PolicySubject], Field(min_length=1)]
    targets: PolicyTargets | None = None
    unenforced_targets: Annotated[
        list[UnenforcedTarget] | None,
        Field(
            description="Read only. The `tool_ref`s of `targets` this deployment cannot currently enforce the policy on: the tool was removed, or another tool now answers to the reference. Absent or empty when it enforces every target; never left out silently when it does not.\n"
        ),
    ] = None
    config: PolicyConfig
    published_at: AwareDatetime | None = None
    updated_at: Timestamp | None = None
    updated_by: Annotated[
        PrincipalRef | None,
        Field(description="Who wrote this version, by id and kind (a policy carries no names).\n"),
    ] = None
    draft_version: Annotated[
        int | None,
        Field(
            description="Read only (rev 11). On a published policy, the version of its pending draft (the draft a replace wrote after the last publish); absent when there is none, and on a policy that was never published, whose read is the draft itself. A row of `GET /v1/policies` carries it as the read does.\n",
            ge=0,
        ),
    ] = None
    retired_at: Annotated[
        Timestamp | None,
        Field(
            description="Read only (rev 11): when the policy was retired (`POST /v1/policies/{id}/retire`). Present on the versions of a retired policy, which `GET /v1/policies/{id}/versions` keeps listing; a retired policy is neither read nor listed otherwise.\n"
        ),
    ] = None
    origin: Annotated[
        PolicyOrigin | None,
        Field(
            description="Read only (rev 11): where this version was imported from, as its write stated it (`PolicyWrite.origin`); absent on a version written without one.\n"
        ),
    ] = None


class SimulateSetRequest(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    policies: Annotated[
        list[PolicyWrite],
        Field(
            description="The proposed bodies. They stand beside the policies in force and never replace one.\n",
            max_length=100,
            min_length=1,
        ),
    ]
    actor: ActorHint | None = None
    action: Action
    resource: Resource | None = None
    context: DecisionContext | None = None
    subject: Annotated[
        PolicySubject | None,
        Field(
            description="Simulate for a hypothetical holder of exactly this subject, as on `POST /v1/policies/{id}/simulate`. Administrators only. The caller remains the token's principal.\n"
        ),
    ] = None


class ApprovalEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Approval
    meta: Meta


class ResolveBatchEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[ResolveBatchResult]
    meta: Meta


class ApprovalListEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[Approval]
    meta: Meta


class PolicyEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: Policy
    meta: Meta


class PolicyListEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    data: list[Policy]
    meta: Meta


class PolicySetEntry(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    role: Annotated[
        Role,
        Field(
            description="`baseline`: the organisation's policy for the tool, which every caller holds (`everyone`). `tightening`: a policy of the agent alone, which only tightens what the baseline and the other policies in force give the agent. `role` (rev 18): a policy for one role of the organisation, which every holder of the role holds beside the baseline. A deployment lists the kinds of row it accepts in `Capabilities.proposals.row_kinds`.\n"
        ),
    ]
    rationale: Annotated[str, Field(max_length=500, min_length=1)]
    assessment: PolicySetAssessment
    policy: PolicyWrite


class PolicySetProposal(BaseModel):
    model_config = ConfigDict(
        extra="allow",
    )
    agent: Annotated[
        Agent1 | None,
        Field(
            description="The agent the proposal is for, a row of `/v1/agents` of the organisation. `principal_id`, when present, is a service principal of the organisation to bind to the agent on approval, as `PUT /v1/agents/{id}/principal` binds it; absent, the agent's binding is left as it is. Rev 18: optional; a proposal without it carries only `baseline` and `role` rows and, optionally, `tools`.\n"
        ),
    ] = None
    tools: Annotated[
        list[PolicySetProposalTool] | None,
        Field(
            description="Tools to register on approval, as `POST /v1/tools` registers them, each owned by the organisation (`owner_kind: org`) and with a `tool_ref` that starts `ext:`.\n",
            max_length=50,
        ),
    ] = None
    policies: Annotated[list[PolicySetEntry], Field(max_length=50, min_length=1)]
    tool_grants: Annotated[
        list[ToolGrant] | None,
        Field(
            description="Rev 18: the `tool_ref`s of tools the organisation already owns (`owner_kind` `org`), to grant to the service principal in `agent.principal_id` on approval (see Tool grants above).\n",
            max_length=50,
            min_length=1,
        ),
    ] = None
