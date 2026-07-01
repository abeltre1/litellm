#!/usr/bin/env python3
"""Provision LiteLLM teams, budgets, and memberships from a declarative access config.

The access config describes providers, projects, and users (see the JSON schema in
``scripts/litellm_access_config.schema.json``). This script reconciles that description
against a running LiteLLM proxy so the proxy's teams/users match the file.

Mapping (kept deliberately simple; policy evaluation is intentionally out of scope):

  - Each project fans out into one LiteLLM team per provider budget allocation. A
    project ``acme`` with allocations for ``openai`` and ``bedrock`` becomes teams
    ``acme-openai`` and ``acme-bedrock``. This is the only faithful mapping because a
    LiteLLM team carries a single ``max_budget`` / ``tpm_limit`` / ``rpm_limit`` /
    ``models`` set, whereas the config's budgets are per provider.
  - A team's ``models`` are the allocation's ``allowed_models`` with the provider's
    ``litellm_prefix`` prepended. ``allowed_models: null`` means "all of this
    provider's models" and maps to the wildcard ``{litellm_prefix}*``. The prefix is
    concatenated verbatim, so include any separator you need in it (e.g. ``openai/``).
  - A team's members are every user who belongs to the owning project, taken as the
    union of ``project.members`` and each user's ``projects`` list.
  - ``user_budget_overrides`` is parsed and validated but not yet applied; it is
    reserved for the future per-user policy work.

Run against a live proxy:

    uv run python scripts/litellm_access_config.py access.yaml \\
        --base-url http://localhost:4000 --api-key "$LITELLM_MASTER_KEY"

Re-runs are idempotent: missing teams/users are created and drifted ones are updated.
Pass ``--prune`` to also delete managed teams (and remove team members) that are no
longer described by the config; without it the script never deletes anything.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from typing import Literal, Mapping, Optional

import requests
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MANAGED_BY = "litellm-access-config"

BudgetDuration = Literal["daily", "weekly", "monthly", "yearly"]

# LiteLLM's duration parser understands s/m/h/d/w/mo but not years, so a yearly
# window is expressed as twelve months.
_BUDGET_DURATION_TO_LITELLM: Mapping[BudgetDuration, str] = {
    "daily": "1d",
    "weekly": "1w",
    "monthly": "1mo",
    "yearly": "12mo",
}

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------- #
# Config models (mirror of the access-config JSON schema)
# --------------------------------------------------------------------------- #
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Defaults(_Strict):
    budget_duration: Optional[BudgetDuration] = None


class ProviderConfig(_Strict):
    litellm_prefix: str = Field(min_length=1)


class BudgetAllocation(_Strict):
    provider: str = Field(min_length=1)
    budget_limit_usd: float = Field(gt=0)
    budget_duration: Optional[BudgetDuration] = None
    tpm_limit: Optional[int] = Field(default=None, ge=1)
    rpm_limit: Optional[int] = Field(default=None, ge=1)
    allowed_models: Optional[tuple[str, ...]] = None

    @field_validator("allowed_models")
    @classmethod
    def _non_empty_unique(cls, value: Optional[tuple[str, ...]]) -> Optional[tuple[str, ...]]:
        if value is None:
            return None
        if len(value) == 0:
            raise ValueError("allowed_models must be null (all models) or a non-empty list")
        if any(len(model) == 0 for model in value):
            raise ValueError("allowed_models entries must be non-empty")
        if len(set(value)) != len(value):
            raise ValueError("allowed_models must not contain duplicates")
        return value


class UserBudgetOverride(_Strict):
    budget_limit_usd: float = Field(gt=0)


class Project(_Strict):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$")
    name: str = Field(min_length=1)
    description: Optional[str] = None
    budget_allocations: tuple[BudgetAllocation, ...] = Field(min_length=1)
    user_budget_overrides: Mapping[str, UserBudgetOverride] = Field(default_factory=dict)
    members: tuple[str, ...] = ()

    @field_validator("budget_allocations")
    @classmethod
    def _one_allocation_per_provider(cls, value: tuple[BudgetAllocation, ...]) -> tuple[BudgetAllocation, ...]:
        providers = tuple(allocation.provider for allocation in value)
        if len(set(providers)) != len(providers):
            raise ValueError("each provider may appear at most once in a project's budget_allocations")
        return value

    @field_validator("members")
    @classmethod
    def _unique_members(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("members must be unique")
        return value


class User(_Strict):
    id: str = Field(min_length=1)
    email: str
    display_name: Optional[str] = None
    projects: tuple[str, ...] = ()

    @field_validator("email")
    @classmethod
    def _email_shape(cls, value: str) -> str:
        if _EMAIL_RE.match(value) is None:
            raise ValueError(f"invalid email address: {value!r}")
        return value

    @field_validator("projects")
    @classmethod
    def _unique_projects(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("a user's projects must be unique")
        return value


class AccessConfig(_Strict):
    providers: Mapping[str, ProviderConfig]
    projects: tuple[Project, ...] = Field(min_length=1)
    users: tuple[User, ...] = Field(min_length=1)
    defaults: Optional[Defaults] = None

    @field_validator("providers")
    @classmethod
    def _at_least_one_provider(cls, value: Mapping[str, ProviderConfig]) -> Mapping[str, ProviderConfig]:
        if len(value) == 0:
            raise ValueError("at least one provider must be defined")
        return value

    @model_validator(mode="after")
    def _referential_integrity(self) -> "AccessConfig":
        project_ids = frozenset(project.id for project in self.projects)
        if len(project_ids) != len(self.projects):
            raise ValueError("project ids must be unique")

        user_ids = frozenset(user.id for user in self.users)
        if len(user_ids) != len(self.users):
            raise ValueError("user ids must be unique")

        provider_names = frozenset(self.providers)
        unknown_allocation_providers = frozenset(
            allocation.provider
            for project in self.projects
            for allocation in project.budget_allocations
            if allocation.provider not in provider_names
        )
        if unknown_allocation_providers:
            raise ValueError(
                "budget_allocations reference unknown providers: " + ", ".join(sorted(unknown_allocation_providers))
            )

        unknown_members = frozenset(
            member for project in self.projects for member in project.members if member not in user_ids
        )
        if unknown_members:
            raise ValueError("project members reference unknown user ids: " + ", ".join(sorted(unknown_members)))

        unknown_user_projects = frozenset(
            project_id for user in self.users for project_id in user.projects if project_id not in project_ids
        )
        if unknown_user_projects:
            raise ValueError(
                "users reference unknown project ids: " + ", ".join(sorted(unknown_user_projects))
            )

        unknown_override_users = frozenset(
            override_user
            for project in self.projects
            for override_user in project.user_budget_overrides
            if override_user not in user_ids
        )
        if unknown_override_users:
            raise ValueError(
                "user_budget_overrides reference unknown user ids: " + ", ".join(sorted(unknown_override_users))
            )
        return self


# --------------------------------------------------------------------------- #
# Desired state (derived purely from the config)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class DesiredTeam:
    team_id: str
    team_alias: str
    project_id: str
    provider: str
    max_budget: float
    budget_duration: Optional[str]
    tpm_limit: Optional[int]
    rpm_limit: Optional[int]
    models: tuple[str, ...]
    member_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class DesiredUser:
    user_id: str
    user_email: str
    user_alias: Optional[str]


@dataclass(frozen=True, slots=True)
class DesiredState:
    teams: tuple[DesiredTeam, ...]
    users: tuple[DesiredUser, ...]


def _team_models(allocation: BudgetAllocation, provider: ProviderConfig) -> tuple[str, ...]:
    if allocation.allowed_models is None:
        return (f"{provider.litellm_prefix}*",)
    return tuple(f"{provider.litellm_prefix}{model}" for model in allocation.allowed_models)


def _resolve_budget_duration(allocation: BudgetAllocation, defaults: Optional[Defaults]) -> Optional[str]:
    duration = allocation.budget_duration or (defaults.budget_duration if defaults else None)
    if duration is None:
        return None
    return _BUDGET_DURATION_TO_LITELLM[duration]


def _project_member_ids(project: Project, users: tuple[User, ...]) -> frozenset[str]:
    from_users = frozenset(user.id for user in users if project.id in user.projects)
    return from_users | frozenset(project.members)


def build_desired_state(config: AccessConfig) -> DesiredState:
    teams = tuple(
        DesiredTeam(
            team_id=f"{project.id}-{allocation.provider}",
            team_alias=f"{project.name} ({allocation.provider})",
            project_id=project.id,
            provider=allocation.provider,
            max_budget=allocation.budget_limit_usd,
            budget_duration=_resolve_budget_duration(allocation, config.defaults),
            tpm_limit=allocation.tpm_limit,
            rpm_limit=allocation.rpm_limit,
            models=_team_models(allocation, config.providers[allocation.provider]),
            member_ids=_project_member_ids(project, config.users),
        )
        for project in config.projects
        for allocation in project.budget_allocations
    )
    users = tuple(
        DesiredUser(user_id=user.id, user_email=user.email, user_alias=user.display_name) for user in config.users
    )
    return DesiredState(teams=teams, users=users)


# --------------------------------------------------------------------------- #
# Current state (read from the proxy)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class CurrentTeam:
    team_id: str
    team_alias: Optional[str]
    max_budget: Optional[float]
    budget_duration: Optional[str]
    tpm_limit: Optional[int]
    rpm_limit: Optional[int]
    models: frozenset[str]
    member_ids: frozenset[str]
    managed: bool


@dataclass(frozen=True, slots=True)
class CurrentUser:
    user_id: str
    user_email: Optional[str]
    user_alias: Optional[str]


@dataclass(frozen=True, slots=True)
class CurrentState:
    teams: Mapping[str, CurrentTeam]
    users: Mapping[str, CurrentUser]


# --------------------------------------------------------------------------- #
# Actions (a tagged union executed against the proxy)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class CreateUser:
    user: DesiredUser


@dataclass(frozen=True, slots=True)
class UpdateUser:
    user: DesiredUser


@dataclass(frozen=True, slots=True)
class CreateTeam:
    team: DesiredTeam


@dataclass(frozen=True, slots=True)
class UpdateTeam:
    team: DesiredTeam


@dataclass(frozen=True, slots=True)
class AddMember:
    team_id: str
    user_id: str


@dataclass(frozen=True, slots=True)
class RemoveMember:
    team_id: str
    user_id: str


@dataclass(frozen=True, slots=True)
class DeleteTeam:
    team_id: str


Action = CreateUser | UpdateUser | CreateTeam | UpdateTeam | AddMember | RemoveMember | DeleteTeam


def _team_needs_update(desired: DesiredTeam, current: CurrentTeam) -> bool:
    return (
        desired.team_alias != current.team_alias
        or desired.max_budget != current.max_budget
        or desired.budget_duration != current.budget_duration
        or desired.tpm_limit != current.tpm_limit
        or desired.rpm_limit != current.rpm_limit
        or frozenset(desired.models) != current.models
    )


def _user_actions(desired: DesiredState, current: CurrentState) -> tuple[Action, ...]:
    creates: tuple[Action, ...] = tuple(
        CreateUser(user) for user in desired.users if user.user_id not in current.users
    )
    updates: tuple[Action, ...] = tuple(
        UpdateUser(user)
        for user in desired.users
        if user.user_id in current.users
        and (
            user.user_email != current.users[user.user_id].user_email
            or user.user_alias != current.users[user.user_id].user_alias
        )
    )
    return creates + updates


def _team_actions(desired: DesiredState, current: CurrentState) -> tuple[Action, ...]:
    creates: tuple[Action, ...] = tuple(
        CreateTeam(team) for team in desired.teams if team.team_id not in current.teams
    )
    updates: tuple[Action, ...] = tuple(
        UpdateTeam(team)
        for team in desired.teams
        if team.team_id in current.teams and _team_needs_update(team, current.teams[team.team_id])
    )
    adds: tuple[Action, ...] = tuple(
        AddMember(team.team_id, user_id)
        for team in desired.teams
        if team.team_id in current.teams
        for user_id in sorted(team.member_ids - current.teams[team.team_id].member_ids)
    )
    return creates + updates + adds


def _prune_actions(desired: DesiredState, current: CurrentState) -> tuple[Action, ...]:
    desired_team_ids = frozenset(team.team_id for team in desired.teams)
    desired_members = {team.team_id: team.member_ids for team in desired.teams}

    removes: tuple[Action, ...] = tuple(
        RemoveMember(team.team_id, user_id)
        for team in current.teams.values()
        if team.managed and team.team_id in desired_team_ids
        for user_id in sorted(team.member_ids - desired_members[team.team_id])
    )
    deletes: tuple[Action, ...] = tuple(
        DeleteTeam(team.team_id)
        for team in current.teams.values()
        if team.managed and team.team_id not in desired_team_ids
    )
    return removes + deletes


def plan(desired: DesiredState, current: CurrentState, prune: bool) -> tuple[Action, ...]:
    """Pure planner: the ordered actions that move ``current`` toward ``desired``.

    Users are created first so they exist before teams reference them, then teams are
    created/updated and members added. Prune actions (member removals, then team
    deletions) run last and only when ``prune`` is set, and only against teams this
    tool manages.
    """
    base = _user_actions(desired, current) + _team_actions(desired, current)
    if not prune:
        return base
    return base + _prune_actions(desired, current)


def describe(action: Action) -> str:
    match action:
        case CreateUser(user):
            return f"create user {user.user_id} <{user.user_email}>"
        case UpdateUser(user):
            return f"update user {user.user_id} <{user.user_email}>"
        case CreateTeam(team):
            return f"create team {team.team_id} (budget ${team.max_budget}, {len(team.member_ids)} members)"
        case UpdateTeam(team):
            return f"update team {team.team_id} (budget ${team.max_budget})"
        case AddMember(team_id, user_id):
            return f"add member {user_id} -> team {team_id}"
        case RemoveMember(team_id, user_id):
            return f"remove member {user_id} from team {team_id}"
        case DeleteTeam(team_id):
            return f"delete team {team_id}"


# --------------------------------------------------------------------------- #
# Proxy I/O
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class ProxyClient:
    base_url: str
    session: requests.Session
    timeout: int

    def _post(self, path: str, body: Mapping[str, object]) -> None:
        response = self.session.post(f"{self.base_url}{path}", json=body, timeout=self.timeout)
        response.raise_for_status()

    def list_teams(self) -> tuple[CurrentTeam, ...]:
        response = self.session.get(f"{self.base_url}/team/list", timeout=self.timeout)
        response.raise_for_status()
        payload = response.json()
        rows = payload if isinstance(payload, list) else payload.get("teams", [])
        return tuple(_parse_current_team(row) for row in rows if isinstance(row, dict))

    def get_user(self, user_id: str) -> Optional[CurrentUser]:
        response = self.session.get(
            f"{self.base_url}/v2/user/info", params={"user_id": user_id}, timeout=self.timeout
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        body = response.json()
        return CurrentUser(
            user_id=body["user_id"],
            user_email=body.get("user_email"),
            user_alias=body.get("user_alias"),
        )

    def apply(self, action: Action) -> None:
        match action:
            case CreateUser(user):
                self._post("/user/new", _new_user_body(user))
            case UpdateUser(user):
                self._post("/user/update", _update_user_body(user))
            case CreateTeam(team):
                self._post("/team/new", _new_team_body(team))
            case UpdateTeam(team):
                self._post("/team/update", _update_team_body(team))
            case AddMember(team_id, user_id):
                self._post("/team/member_add", {"team_id": team_id, "member": {"user_id": user_id, "role": "user"}})
            case RemoveMember(team_id, user_id):
                self._post("/team/member_delete", {"team_id": team_id, "user_id": user_id})
            case DeleteTeam(team_id):
                self._post("/team/delete", {"team_ids": [team_id]})


def _parse_current_team(row: Mapping[str, object]) -> CurrentTeam:
    metadata = row.get("metadata")
    managed = isinstance(metadata, dict) and metadata.get("managed_by") == MANAGED_BY
    members_with_roles = row.get("members_with_roles")
    member_ids = frozenset(
        member["user_id"]
        for member in (members_with_roles if isinstance(members_with_roles, list) else [])
        if isinstance(member, dict) and member.get("user_id")
    )
    models = row.get("models")
    return CurrentTeam(
        team_id=str(row["team_id"]),
        team_alias=_opt_str(row.get("team_alias")),
        max_budget=_opt_float(row.get("max_budget")),
        budget_duration=_opt_str(row.get("budget_duration")),
        tpm_limit=_opt_int(row.get("tpm_limit")),
        rpm_limit=_opt_int(row.get("rpm_limit")),
        models=frozenset(str(model) for model in models) if isinstance(models, list) else frozenset(),
        member_ids=member_ids,
        managed=managed,
    )


def _opt_str(value: object) -> Optional[str]:
    return value if isinstance(value, str) else None


def _opt_int(value: object) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _opt_float(value: object) -> Optional[float]:
    if isinstance(value, bool):
        return None
    return float(value) if isinstance(value, (int, float)) else None


def _team_metadata(team: DesiredTeam) -> dict[str, str]:
    return {"managed_by": MANAGED_BY, "project_id": team.project_id, "provider": team.provider}


def _new_team_body(team: DesiredTeam) -> dict[str, object]:
    return {
        "team_id": team.team_id,
        "team_alias": team.team_alias,
        "max_budget": team.max_budget,
        "budget_duration": team.budget_duration,
        "tpm_limit": team.tpm_limit,
        "rpm_limit": team.rpm_limit,
        "models": list(team.models),
        "members_with_roles": [{"user_id": user_id, "role": "user"} for user_id in sorted(team.member_ids)],
        "metadata": _team_metadata(team),
    }


def _update_team_body(team: DesiredTeam) -> dict[str, object]:
    return {
        "team_id": team.team_id,
        "team_alias": team.team_alias,
        "max_budget": team.max_budget,
        "budget_duration": team.budget_duration,
        "tpm_limit": team.tpm_limit,
        "rpm_limit": team.rpm_limit,
        "models": list(team.models),
        "metadata": _team_metadata(team),
    }


def _new_user_body(user: DesiredUser) -> dict[str, object]:
    return {
        "user_id": user.user_id,
        "user_email": user.user_email,
        "user_alias": user.user_alias,
        "user_role": "internal_user",
        "auto_create_key": False,
    }


def _update_user_body(user: DesiredUser) -> dict[str, object]:
    return {"user_id": user.user_id, "user_email": user.user_email, "user_alias": user.user_alias}


def fetch_current_state(client: ProxyClient, desired: DesiredState) -> CurrentState:
    teams = {team.team_id: team for team in client.list_teams()}
    users = {
        user.user_id: user
        for user in (client.get_user(desired_user.user_id) for desired_user in desired.users)
        if user is not None
    }
    return CurrentState(teams=teams, users=users)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def load_config(path: str) -> AccessConfig:
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"config root must be a mapping, got {type(raw).__name__}")
    return AccessConfig.model_validate(raw)


def _parse_args(argv: tuple[str, ...]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reconcile LiteLLM teams/users from an access config file.")
    parser.add_argument("config", help="Path to the access config (JSON or YAML).")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("LITELLM_BASE_URL", "http://localhost:4000"),
        help="Proxy base URL (default: $LITELLM_BASE_URL or http://localhost:4000).",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("LITELLM_API_KEY") or os.environ.get("LITELLM_MASTER_KEY"),
        help="Admin API key (default: $LITELLM_API_KEY or $LITELLM_MASTER_KEY).",
    )
    parser.add_argument("--timeout", type=int, default=30, help="Per-request timeout in seconds (default: 30).")
    parser.add_argument("--dry-run", action="store_true", help="Print the plan without calling the proxy.")
    parser.add_argument(
        "--prune",
        action="store_true",
        help="Delete managed teams and remove team members no longer present in the config.",
    )
    return parser.parse_args(argv)


def _make_client(base_url: str, api_key: Optional[str], timeout: int) -> ProxyClient:
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    if api_key:
        session.headers.update({"Authorization": f"Bearer {api_key}"})
    return ProxyClient(base_url=base_url.rstrip("/"), session=session, timeout=timeout)


def main(argv: tuple[str, ...]) -> int:
    args = _parse_args(argv)
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    desired = build_desired_state(config)

    if args.dry_run:
        empty = CurrentState(teams={}, users={})
        actions = plan(desired, empty, args.prune)
        print(f"dry run against an empty proxy would apply {len(actions)} action(s):")
        for action in actions:
            print(f"  - {describe(action)}")
        return 0

    client = _make_client(args.base_url, args.api_key, args.timeout)
    try:
        current = fetch_current_state(client, desired)
        actions = plan(desired, current, args.prune)
        if not actions:
            print("already in sync; nothing to do")
            return 0
        print(f"applying {len(actions)} action(s):")
        for action in actions:
            print(f"  - {describe(action)}")
            client.apply(action)
    except requests.RequestException as error:
        print(f"error: request to proxy failed: {error}", file=sys.stderr)
        return 1
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(tuple(sys.argv[1:])))
