"""Tests for scripts/litellm_access_config.py.

The planner and desired-state derivation are pure, so these tests pin the exact
behavior a mutation would break: the (project, provider) team fan-out, the model-name
prefixing and wildcard, the budget-duration mapping, membership union, idempotent
diffing, and the prune gating (managed-only, never without the flag).
"""

import dataclasses
import importlib.util
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MODULE_PATH = _REPO_ROOT / "scripts" / "litellm_access_config.py"
_spec = importlib.util.spec_from_file_location("litellm_access_config", _MODULE_PATH)
assert _spec is not None and _spec.loader is not None
mod = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = mod
_spec.loader.exec_module(mod)


def _base_config() -> dict:
    return {
        "providers": {
            "openai": {"litellm_prefix": "openai/"},
            "bedrock": {"litellm_prefix": "bedrock/"},
        },
        "projects": [
            {
                "id": "acme",
                "name": "Acme",
                "budget_allocations": [
                    {
                        "provider": "openai",
                        "budget_limit_usd": 100.0,
                        "budget_duration": "monthly",
                        "tpm_limit": 1000,
                        "rpm_limit": 60,
                        "allowed_models": ["gpt-4o", "gpt-4o-mini"],
                    },
                    {
                        "provider": "bedrock",
                        "budget_limit_usd": 50.0,
                        "allowed_models": None,
                    },
                ],
                "members": ["u1"],
            }
        ],
        "users": [
            {"id": "u1", "email": "u1@example.com", "display_name": "User One", "projects": ["acme"]},
            {"id": "u2", "email": "u2@example.com", "projects": ["acme"]},
        ],
    }


# --------------------------------------------------------------------------- #
# Config validation
# --------------------------------------------------------------------------- #
def test_valid_config_parses():
    config = mod.AccessConfig.model_validate(_base_config())
    assert tuple(config.providers) == ("openai", "bedrock")
    assert len(config.projects) == 1


def test_unknown_allocation_provider_rejected():
    cfg = _base_config()
    cfg["projects"][0]["budget_allocations"][0]["provider"] = "ghost"
    with pytest.raises(ValidationError, match="unknown providers"):
        mod.AccessConfig.model_validate(cfg)


def test_project_member_must_be_known_user():
    cfg = _base_config()
    cfg["projects"][0]["members"] = ["nobody"]
    with pytest.raises(ValidationError, match="unknown user ids"):
        mod.AccessConfig.model_validate(cfg)


def test_user_project_must_exist():
    cfg = _base_config()
    cfg["users"][0]["projects"] = ["missing"]
    with pytest.raises(ValidationError, match="unknown project ids"):
        mod.AccessConfig.model_validate(cfg)


def test_user_budget_override_must_reference_known_user():
    cfg = _base_config()
    cfg["projects"][0]["user_budget_overrides"] = {"ghost": {"budget_limit_usd": 5.0}}
    with pytest.raises(ValidationError, match="user_budget_overrides reference unknown"):
        mod.AccessConfig.model_validate(cfg)


def test_duplicate_provider_allocation_rejected():
    cfg = _base_config()
    cfg["projects"][0]["budget_allocations"].append({"provider": "openai", "budget_limit_usd": 1.0})
    with pytest.raises(ValidationError, match="at most once"):
        mod.AccessConfig.model_validate(cfg)


def test_duplicate_project_ids_rejected():
    cfg = _base_config()
    cfg["projects"].append(dict(cfg["projects"][0]))
    with pytest.raises(ValidationError, match="project ids must be unique"):
        mod.AccessConfig.model_validate(cfg)


def test_invalid_project_id_pattern_rejected():
    cfg = _base_config()
    cfg["projects"][0]["id"] = "Acme_Corp"
    with pytest.raises(ValidationError):
        mod.AccessConfig.model_validate(cfg)


def test_bad_email_rejected():
    cfg = _base_config()
    cfg["users"][0]["email"] = "not-an-email"
    with pytest.raises(ValidationError, match="invalid email"):
        mod.AccessConfig.model_validate(cfg)


def test_empty_providers_rejected():
    cfg = _base_config()
    cfg["providers"] = {}
    with pytest.raises(ValidationError):
        mod.AccessConfig.model_validate(cfg)


def test_zero_budget_rejected():
    cfg = _base_config()
    cfg["projects"][0]["budget_allocations"][0]["budget_limit_usd"] = 0
    with pytest.raises(ValidationError):
        mod.AccessConfig.model_validate(cfg)


def test_allowed_models_empty_list_rejected():
    cfg = _base_config()
    cfg["projects"][0]["budget_allocations"][0]["allowed_models"] = []
    with pytest.raises(ValidationError, match="non-empty"):
        mod.AccessConfig.model_validate(cfg)


def test_allowed_models_duplicates_rejected():
    cfg = _base_config()
    cfg["projects"][0]["budget_allocations"][0]["allowed_models"] = ["gpt-4o", "gpt-4o"]
    with pytest.raises(ValidationError, match="duplicates"):
        mod.AccessConfig.model_validate(cfg)


def test_extra_keys_rejected():
    cfg = _base_config()
    cfg["projects"][0]["surprise"] = True
    with pytest.raises(ValidationError):
        mod.AccessConfig.model_validate(cfg)


# --------------------------------------------------------------------------- #
# Desired-state derivation
# --------------------------------------------------------------------------- #
def _desired():
    return mod.build_desired_state(mod.AccessConfig.model_validate(_base_config()))


def _team(desired, team_id):
    return next(t for t in desired.teams if t.team_id == team_id)


def test_one_team_per_project_provider():
    desired = _desired()
    assert {t.team_id for t in desired.teams} == {"acme-openai", "acme-bedrock"}


def test_team_alias_includes_provider():
    assert _team(_desired(), "acme-openai").team_alias == "Acme (openai)"


def test_models_are_prefixed():
    assert _team(_desired(), "acme-openai").models == ("openai/gpt-4o", "openai/gpt-4o-mini")


def test_null_allowed_models_becomes_wildcard():
    assert _team(_desired(), "acme-bedrock").models == ("bedrock/*",)


def test_budget_and_limits_passthrough():
    openai_team = _team(_desired(), "acme-openai")
    assert openai_team.max_budget == 100.0
    assert openai_team.tpm_limit == 1000
    assert openai_team.rpm_limit == 60


def test_budget_duration_mapping():
    assert _team(_desired(), "acme-openai").budget_duration == "1mo"


def test_budget_duration_falls_back_to_defaults():
    cfg = _base_config()
    cfg["defaults"] = {"budget_duration": "weekly"}
    # bedrock allocation has no explicit duration, so it inherits the default
    desired = mod.build_desired_state(mod.AccessConfig.model_validate(cfg))
    assert _team(desired, "acme-bedrock").budget_duration == "1w"
    # openai keeps its explicit monthly duration
    assert _team(desired, "acme-openai").budget_duration == "1mo"


def test_budget_duration_absent_is_none():
    assert _team(_desired(), "acme-bedrock").budget_duration is None


def test_yearly_maps_to_twelve_months():
    cfg = _base_config()
    cfg["projects"][0]["budget_allocations"][1]["budget_duration"] = "yearly"
    desired = mod.build_desired_state(mod.AccessConfig.model_validate(cfg))
    assert _team(desired, "acme-bedrock").budget_duration == "12mo"


def test_membership_is_union_of_members_and_user_projects():
    # u1 via project.members AND user.projects; u2 only via user.projects
    members = _team(_desired(), "acme-openai").member_ids
    assert members == frozenset({"u1", "u2"})


def test_desired_users_carry_display_name_as_alias():
    desired = _desired()
    u1 = next(u for u in desired.users if u.user_id == "u1")
    u2 = next(u for u in desired.users if u.user_id == "u2")
    assert u1.user_alias == "User One"
    assert u2.user_alias is None


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #
def _current_from_desired(desired, *, managed=True):
    """A CurrentState that exactly matches desired (the idempotent fixed point)."""
    teams = {
        t.team_id: mod.CurrentTeam(
            team_id=t.team_id,
            team_alias=t.team_alias,
            max_budget=t.max_budget,
            budget_duration=t.budget_duration,
            tpm_limit=t.tpm_limit,
            rpm_limit=t.rpm_limit,
            models=frozenset(t.models),
            member_ids=t.member_ids,
            managed=managed,
        )
        for t in desired.teams
    }
    users = {
        u.user_id: mod.CurrentUser(user_id=u.user_id, user_email=u.user_email, user_alias=u.user_alias)
        for u in desired.users
    }
    return mod.CurrentState(teams=teams, users=users)


def test_plan_from_empty_creates_everything():
    desired = _desired()
    actions = mod.plan(desired, mod.CurrentState(teams={}, users={}), prune=False)
    creates_users = [a for a in actions if isinstance(a, mod.CreateUser)]
    creates_teams = [a for a in actions if isinstance(a, mod.CreateTeam)]
    assert {a.user.user_id for a in creates_users} == {"u1", "u2"}
    assert {a.team.team_id for a in creates_teams} == {"acme-openai", "acme-bedrock"}
    # no AddMember actions: brand-new teams carry members in the create payload
    assert not [a for a in actions if isinstance(a, mod.AddMember)]


def test_users_are_created_before_teams():
    desired = _desired()
    actions = mod.plan(desired, mod.CurrentState(teams={}, users={}), prune=False)
    last_user = max(i for i, a in enumerate(actions) if isinstance(a, mod.CreateUser))
    first_team = min(i for i, a in enumerate(actions) if isinstance(a, mod.CreateTeam))
    assert last_user < first_team


def test_plan_is_idempotent_when_in_sync():
    desired = _desired()
    assert mod.plan(desired, _current_from_desired(desired), prune=False) == ()


def test_budget_drift_triggers_update():
    desired = _desired()
    current = _current_from_desired(desired)
    drifted = dataclasses.replace(current.teams["acme-openai"], max_budget=1.0)
    current = mod.CurrentState(teams={**current.teams, "acme-openai": drifted}, users=current.users)
    updates = [a for a in mod.plan(desired, current, prune=False) if isinstance(a, mod.UpdateTeam)]
    assert [a.team.team_id for a in updates] == ["acme-openai"]


def test_model_drift_triggers_update():
    desired = _desired()
    current = _current_from_desired(desired)
    drifted = dataclasses.replace(current.teams["acme-openai"], models=frozenset({"openai/gpt-4o"}))
    current = mod.CurrentState(teams={**current.teams, "acme-openai": drifted}, users=current.users)
    updates = [a for a in mod.plan(desired, current, prune=False) if isinstance(a, mod.UpdateTeam)]
    assert [a.team.team_id for a in updates] == ["acme-openai"]


def test_user_email_drift_triggers_update():
    desired = _desired()
    current = _current_from_desired(desired)
    drifted = mod.CurrentUser(user_id="u1", user_email="old@example.com", user_alias="User One")
    current = mod.CurrentState(teams=current.teams, users={**current.users, "u1": drifted})
    updates = [a for a in mod.plan(desired, current, prune=False) if isinstance(a, mod.UpdateUser)]
    assert [a.user.user_id for a in updates] == ["u1"]


def test_missing_member_on_existing_team_is_added():
    desired = _desired()
    current = _current_from_desired(desired)
    stripped = dataclasses.replace(current.teams["acme-openai"], member_ids=frozenset({"u1"}))
    current = mod.CurrentState(teams={**current.teams, "acme-openai": stripped}, users=current.users)
    adds = [a for a in mod.plan(desired, current, prune=False) if isinstance(a, mod.AddMember)]
    assert adds == [mod.AddMember("acme-openai", "u2")]


def test_extra_member_not_removed_without_prune():
    desired = _desired()
    current = _current_from_desired(desired)
    extra = dataclasses.replace(current.teams["acme-openai"], member_ids=frozenset({"u1", "u2", "u3"}))
    current = mod.CurrentState(teams={**current.teams, "acme-openai": extra}, users=current.users)
    assert not [a for a in mod.plan(desired, current, prune=False) if isinstance(a, mod.RemoveMember)]


def test_prune_removes_extra_member_on_managed_team():
    desired = _desired()
    current = _current_from_desired(desired)
    extra = dataclasses.replace(current.teams["acme-openai"], member_ids=frozenset({"u1", "u2", "u3"}))
    current = mod.CurrentState(teams={**current.teams, "acme-openai": extra}, users=current.users)
    removes = [a for a in mod.plan(desired, current, prune=True) if isinstance(a, mod.RemoveMember)]
    assert removes == [mod.RemoveMember("acme-openai", "u3")]


def test_prune_deletes_managed_team_not_in_config():
    desired = _desired()
    current = _current_from_desired(desired)
    orphan = mod.CurrentTeam(
        team_id="old-openai",
        team_alias="Old (openai)",
        max_budget=10.0,
        budget_duration=None,
        tpm_limit=None,
        rpm_limit=None,
        models=frozenset({"openai/*"}),
        member_ids=frozenset(),
        managed=True,
    )
    current = mod.CurrentState(teams={**current.teams, "old-openai": orphan}, users=current.users)
    deletes = [a for a in mod.plan(desired, current, prune=True) if isinstance(a, mod.DeleteTeam)]
    assert deletes == [mod.DeleteTeam("old-openai")]


def test_prune_ignores_unmanaged_teams():
    desired = _desired()
    current = _current_from_desired(desired)
    foreign = mod.CurrentTeam(
        team_id="handmade",
        team_alias="Handmade",
        max_budget=10.0,
        budget_duration=None,
        tpm_limit=None,
        rpm_limit=None,
        models=frozenset(),
        member_ids=frozenset({"someone"}),
        managed=False,
    )
    current = mod.CurrentState(teams={**current.teams, "handmade": foreign}, users=current.users)
    actions = mod.plan(desired, current, prune=True)
    assert not [a for a in actions if isinstance(a, (mod.DeleteTeam, mod.RemoveMember))]


# --------------------------------------------------------------------------- #
# Request bodies and current-state parsing
# --------------------------------------------------------------------------- #
def test_new_team_body_tags_managed_and_sorts_members():
    team = _team(_desired(), "acme-openai")
    body = mod._new_team_body(team)
    assert body["metadata"] == {"managed_by": mod.MANAGED_BY, "project_id": "acme", "provider": "openai"}
    assert body["members_with_roles"] == [{"user_id": "u1", "role": "user"}, {"user_id": "u2", "role": "user"}]
    assert body["max_budget"] == 100.0


def test_new_user_body_does_not_mint_a_key():
    body = mod._new_user_body(mod.DesiredUser("u1", "u1@example.com", "User One"))
    assert body["auto_create_key"] is False
    assert body["user_id"] == "u1"


def test_parse_current_team_detects_managed_flag_and_members():
    row = {
        "team_id": "acme-openai",
        "team_alias": "Acme (openai)",
        "max_budget": 100.0,
        "budget_duration": "1mo",
        "tpm_limit": 1000,
        "rpm_limit": 60,
        "models": ["openai/gpt-4o"],
        "members_with_roles": [{"user_id": "u1", "role": "admin"}, {"role": "user"}],
        "metadata": {"managed_by": mod.MANAGED_BY, "project_id": "acme"},
    }
    parsed = mod._parse_current_team(row)
    assert parsed.managed is True
    assert parsed.member_ids == frozenset({"u1"})
    assert parsed.models == frozenset({"openai/gpt-4o"})


def test_parse_current_team_unmanaged_when_tag_missing():
    row = {"team_id": "x", "metadata": {"managed_by": "someone-else"}}
    assert mod._parse_current_team(row).managed is False


def test_parse_current_team_handles_missing_metadata():
    parsed = mod._parse_current_team({"team_id": "x"})
    assert parsed.managed is False
    assert parsed.member_ids == frozenset()
    assert parsed.models == frozenset()


def test_describe_covers_every_action_variant():
    actions = [
        mod.CreateUser(mod.DesiredUser("u", "u@e.com", None)),
        mod.UpdateUser(mod.DesiredUser("u", "u@e.com", None)),
        mod.CreateTeam(_team(_desired(), "acme-openai")),
        mod.UpdateTeam(_team(_desired(), "acme-openai")),
        mod.AddMember("t", "u"),
        mod.RemoveMember("t", "u"),
        mod.DeleteTeam("t"),
    ]
    for action in actions:
        assert isinstance(mod.describe(action), str) and mod.describe(action)
