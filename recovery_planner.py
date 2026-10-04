"""
recovery_planner.py

Risk-Aware Recovery Controller
Production Reliability + Controlled Automation

Responsibilities:
- Convert incident assessments into recovery plans.
- Rank recovery actions by risk, impact, and expected benefit.
- Respect service dependencies and recovery ordering.
- Enforce policy constraints from recovery_policies.yaml.
- Require approval for high-risk and critical actions.
- Prevent duplicate and conflicting actions within a plan.
- Generate plans for dry-run review before execution.

This module plans recovery actions only. It does not execute them.
"""

from __future__ import annotations

import logging
import uuid

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml


logger = logging.getLogger("recovery_planner")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PlanStatus(str, Enum):
    CREATED = "created"
    REQUIRES_APPROVAL = "requires_approval"
    BLOCKED = "blocked"
    READY = "ready"
    COMPLETED = "completed"


class ActionPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IncidentAssessment:
    """Normalized assessment produced by the incident and risk modules."""

    incident_id: str
    service: str
    severity: str
    risk_level: RiskLevel

    symptoms: list[str] = field(default_factory=list)
    suspected_causes: list[str] = field(default_factory=list)
    affected_services: list[str] = field(default_factory=list)

    confidence: float = 0.0
    impact_score: float = 0.0
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class RecoveryActionPlan:
    """A proposed action that can be passed to recovery_executor.py."""

    action_id: str
    action_type: str
    service: str
    description: str

    risk_level: RiskLevel
    priority: ActionPriority

    parameters: dict[str, Any] = field(default_factory=dict)
    rollback_action_type: str | None = None
    rollback_parameters: dict[str, Any] = field(default_factory=dict)

    requires_approval: bool = False
    approved: bool = False
    approval_reference: str | None = None

    timeout_seconds: float = 30.0
    max_attempts: int = 1
    expected_health: str = "healthy"

    rationale: str = ""
    dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["risk_level"] = self.risk_level.value
        result["priority"] = self.priority.value
        return result


@dataclass
class RecoveryPlan:
    """Complete recovery plan for one incident."""

    plan_id: str
    incident_id: str
    primary_service: str

    status: PlanStatus
    risk_level: RiskLevel

    actions: list[RecoveryActionPlan] = field(default_factory=list)
    blocked_reasons: list[str] = field(default_factory=list)
    approval_required: bool = False

    created_at: str = ""
    rationale: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "incident_id": self.incident_id,
            "primary_service": self.primary_service,
            "status": self.status.value,
            "risk_level": self.risk_level.value,
            "actions": [action.to_dict() for action in self.actions],
            "blocked_reasons": self.blocked_reasons,
            "approval_required": self.approval_required,
            "created_at": self.created_at,
            "rationale": self.rationale,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Recovery planner
# ---------------------------------------------------------------------------


class RecoveryPlanner:
    """
    Builds policy-aware recovery plans from incident assessments.

    Expected policy file structure:

    risk:
      approval_required_levels:
        - high
        - critical
      maximum_automatic_risk: medium

    execution:
      default_timeout_seconds: 30
      maximum_attempts: 3

    actions:
      restart_service:
        enabled: true
        risk_level: medium
        requires_approval: false
        priority: high
        timeout_seconds: 30
        max_attempts: 2
        rollback_action_type: restore_service
        expected_health: healthy
        description: Restart an unhealthy service
        parameters:
          reason: incident_recovery

    service_recovery:
      api:
        allowed_actions:
          - restart_service

    Action definitions must be explicitly configured. The planner does not
    invent executable operations from free-form incident descriptions.
    """

    def __init__(
        self,
        *,
        policy_path: str | Path = "recovery_policies.yaml",
        dependency_path: str | Path = "service_dependencies.yaml",
    ) -> None:
        self.policy_path = Path(policy_path)
        self.dependency_path = Path(dependency_path)

        self.policies = self._load_yaml(self.policy_path)
        self.dependencies = self._load_yaml(self.dependency_path)

        self._validate_configuration()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def create_plan(
        self,
        assessment: IncidentAssessment,
        *,
        requested_actions: Sequence[str] | None = None,
        approval_references: Mapping[str, str] | None = None,
    ) -> RecoveryPlan:
        """
        Create a recovery plan from a risk assessment.

        requested_actions:
            Optional explicit list of configured action types to consider.

        approval_references:
            Optional mapping of action type to an external approval reference.
            Supplying a reference does not automatically mean the action is
            approved; the executor's approval process must validate it.
        """

        self._validate_assessment(assessment)

        approval_references = approval_references or {}
        plan_id = str(uuid.uuid4())
        created_at = self._utc_now()

        plan = RecoveryPlan(
            plan_id=plan_id,
            incident_id=assessment.incident_id,
            primary_service=assessment.service,
            status=PlanStatus.CREATED,
            risk_level=assessment.risk_level,
            created_at=created_at,
            rationale=(
                "Plan generated from incident assessment and configured "
                "recovery policies."
            ),
            metadata={
                "assessment_confidence": assessment.confidence,
                "impact_score": assessment.impact_score,
                "affected_services": list(assessment.affected_services),
            },
        )

        action_names = self._select_actions(
            assessment=assessment,
            requested_actions=requested_actions,
        )

        if not action_names:
            plan.status = PlanStatus.BLOCKED
            plan.blocked_reasons.append(
                "No eligible recovery actions were found in the configured "
                "policies."
            )
            return plan

        service_order = self._get_recovery_order(
            assessment.service,
            assessment.affected_services,
        )

        candidates: list[RecoveryActionPlan] = []

        for service in service_order:
            for action_type in action_names:
                action_config = self._get_action_config(action_type)

                if not action_config:
                    plan.blocked_reasons.append(
                        f"Action '{action_type}' has no policy configuration."
                    )
                    continue

                if not action_config.get("enabled", False):
                    continue

                if not self._service_allows_action(service, action_type):
                    continue

                candidate = self._build_action(
                    action_type=action_type,
                    service=service,
                    action_config=action_config,
                    assessment=assessment,
                    approval_reference=approval_references.get(action_type),
                )

                if candidate is not None:
                    candidates.append(candidate)

        candidates = self._remove_conflicts(candidates)

        if not candidates:
            plan.status = PlanStatus.BLOCKED

            if not plan.blocked_reasons:
                plan.blocked_reasons.append(
                    "Configured policies did not permit a recovery action "
                    "for the affected services."
                )

            return plan

        plan.actions = self._sort_actions(candidates)

        plan.approval_required = any(
            action.requires_approval and not action.approved
            for action in plan.actions
        )

        if plan.blocked_reasons:
            plan.status = PlanStatus.BLOCKED
        elif plan.approval_required:
            plan.status = PlanStatus.REQUIRES_APPROVAL
        else:
            plan.status = PlanStatus.READY

        logger.info(
            "Created recovery plan %s for incident %s with status %s.",
            plan.plan_id,
            plan.incident_id,
            plan.status.value,
        )

        return plan

    def validate_plan(self, plan: RecoveryPlan) -> list[str]:
        """
        Validate a plan before handing it to the executor.

        Returns a list of validation errors. An empty list means the plan
        passed this module's structural and policy checks.
        """

        errors: list[str] = []

        if not plan.incident_id:
            errors.append("Plan is missing an incident ID.")

        if not plan.actions:
            errors.append("Plan contains no recovery actions.")

        seen: set[tuple[str, str]] = set()

        for action in plan.actions:
            key = (action.service, action.action_type)

            if key in seen:
                errors.append(
                    f"Duplicate action '{action.action_type}' for "
                    f"service '{action.service}'."
                )

            seen.add(key)

            action_config = self._get_action_config(action.action_type)

            if not action_config:
                errors.append(
                    f"Action '{action.action_type}' is not configured."
                )
                continue

            if not action_config.get("enabled", False):
                errors.append(
                    f"Action '{action.action_type}' is disabled by policy."
                )

            if not self._service_allows_action(
                action.service,
                action.action_type,
            ):
                errors.append(
                    f"Policy does not allow '{action.action_type}' "
                    f"for service '{action.service}'."
                )

            if (
                action.requires_approval
                and not action.approved
                and plan.status == PlanStatus.READY
            ):
                errors.append(
                    f"Action '{action.action_type}' requires approval, "
                    "but the plan is marked ready."
                )

        if plan.status == PlanStatus.BLOCKED:
            errors.append("Plan is blocked by policy or planning errors.")

        return errors

    # -----------------------------------------------------------------------
    # Candidate selection
    # -----------------------------------------------------------------------

    def _select_actions(
        self,
        *,
        assessment: IncidentAssessment,
        requested_actions: Sequence[str] | None,
    ) -> list[str]:
        configured_actions = self.policies.get("actions", {})

        if requested_actions is not None:
            selected: list[str] = []

            for action_type in requested_actions:
                if action_type not in configured_actions:
                    logger.warning(
                        "Requested action '%s' is not configured.",
                        action_type,
                    )
                    continue

                selected.append(action_type)

            return list(dict.fromkeys(selected))

        # Policies may define action selection based on incident symptoms.
        selection_rules = self.policies.get("selection_rules", [])
        selected_actions: list[str] = []

        symptoms = {
            self._normalize_text(item)
            for item in assessment.symptoms
        }

        causes = {
            self._normalize_text(item)
            for item in assessment.suspected_causes
        }

        for rule in selection_rules:
            if not isinstance(rule, Mapping):
                continue

            if not rule.get("enabled", True):
                continue

            match_symptoms = {
                self._normalize_text(item)
                for item in rule.get("symptoms", [])
            }

            match_causes = {
                self._normalize_text(item)
                for item in rule.get("suspected_causes", [])
            }

            symptom_match = bool(match_symptoms.intersection(symptoms))
            cause_match = bool(match_causes.intersection(causes))

            if (
                (match_symptoms or match_causes)
                and not symptom_match
                and not cause_match
            ):
                continue

            for action_type in rule.get("actions", []):
                if action_type in configured_actions:
                    selected_actions.append(action_type)

        # No generic or arbitrary action is invented when no rule matches.
        return list(dict.fromkeys(selected_actions))

    # -----------------------------------------------------------------------
    # Action construction and risk controls
    # -----------------------------------------------------------------------

    def _build_action(
        self,
        *,
        action_type: str,
        service: str,
        action_config: Mapping[str, Any],
        assessment: IncidentAssessment,
        approval_reference: str | None,
    ) -> RecoveryActionPlan | None:
        try:
            action_risk = RiskLevel(
                str(action_config.get("risk_level", "medium")).lower()
            )
            priority = ActionPriority(
                str(action_config.get("priority", "normal")).lower()
            )
        except ValueError:
            logger.error(
                "Invalid risk level or priority for action '%s'.",
                action_type,
            )
            return None

        if not self._risk_allowed(action_risk, assessment.risk_level):
            logger.warning(
                "Action '%s' rejected because of risk policy.",
                action_type,
            )
            return None

        requires_approval = bool(
            action_config.get("requires_approval", False)
        )

        approval_levels = self.policies.get("risk", {}).get(
            "approval_required_levels",
            ["high", "critical"],
        )

        if action_risk.value in approval_levels:
            requires_approval = True

        # A reference is not equivalent to approval. The external approval
        # workflow must validate it and set approved=True before execution.
        approved = False

        return RecoveryActionPlan(
            action_id=str(uuid.uuid4()),
            action_type=action_type,
            service=service,
            description=str(
                action_config.get(
                    "description",
                    f"Execute configured recovery action '{action_type}'.",
                )
            ),
            risk_level=action_risk,
            priority=priority,
            parameters=dict(action_config.get("parameters", {})),
            rollback_action_type=action_config.get(
                "rollback_action_type"
            ),
            rollback_parameters=dict(
                action_config.get("rollback_parameters", {})
            ),
            requires_approval=requires_approval,
            approved=approved,
            approval_reference=approval_reference,
            timeout_seconds=float(
                action_config.get(
                    "timeout_seconds",
                    self.policies.get("execution", {}).get(
                        "default_timeout_seconds",
                        30,
                    ),
                )
            ),
            max_attempts=int(
                action_config.get(
                    "max_attempts",
                    self.policies.get("execution", {}).get(
                        "maximum_attempts",
                        1,
                    ),
                )
            ),
            expected_health=str(
                action_config.get("expected_health", "healthy")
            ),
            rationale=(
                f"Selected for service '{service}' based on configured "
                f"policy and incident risk '{assessment.risk_level.value}'."
            ),
            dependencies=self._service_dependencies(service),
        )

    def _risk_allowed(
        self,
        action_risk: RiskLevel,
        incident_risk: RiskLevel,
    ) -> bool:
        """
        Reject actions above the configured automatic risk ceiling.

        High-risk actions can still appear in a plan when the policy explicitly
        permits them; they will require approval before execution.
        """

        risk_config = self.policies.get("risk", {})
        maximum_risk = str(
            risk_config.get("maximum_planned_risk", "critical")
        ).lower()

        risk_order = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }

        try:
            maximum_allowed = RiskLevel(maximum_risk)
        except ValueError:
            logger.error("Invalid maximum_planned_risk policy.")
            return False

        if risk_order[action_risk] > risk_order[maximum_allowed]:
            return False

        # Avoid automatic actions whose risk exceeds the incident assessment
        # unless the policy explicitly allows escalation.
        allow_escalation = bool(
            risk_config.get("allow_action_risk_escalation", False)
        )

        if (
            risk_order[action_risk] > risk_order[incident_risk]
            and not allow_escalation
        ):
            return False

        return True

    # -----------------------------------------------------------------------
    # Dependency ordering
    # -----------------------------------------------------------------------

    def _get_recovery_order(
        self,
        primary_service: str,
        affected_services: Sequence[str],
    ) -> list[str]:
        """
        Return a dependency-aware service order.

        Dependencies are interpreted as services that must be considered
        before the service that depends on them. For example, if api depends
        on database, database is ordered before api.
        """

        known_services = set(affected_services)
        known_services.add(primary_service)

        dependency_map = self.dependencies.get("services", {})
        ordered: list[str] = []
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(service: str) -> None:
            if service in visited:
                return

            if service in visiting:
                logger.warning(
                    "Dependency cycle detected at service '%s'.",
                    service,
                )
                return

            visiting.add(service)

            service_config = dependency_map.get(service, {})
            dependencies = service_config.get("depends_on", [])

            for dependency in dependencies:
                if dependency in known_services:
                    visit(dependency)

            visiting.remove(service)
            visited.add(service)
            ordered.append(service)

        for service in sorted(known_services):
            visit(service)

        return ordered

    def _service_dependencies(self, service: str) -> list[str]:
        service_config = self.dependencies.get("services", {}).get(
            service,
            {},
        )

        return list(service_config.get("depends_on", []))

    def _service_allows_action(
        self,
        service: str,
        action_type: str,
    ) -> bool:
        service_recovery = self.policies.get("service_recovery", {})

        # If no per-service rule exists, fail closed.
        service_config = service_recovery.get(service)

        if not isinstance(service_config, Mapping):
            return False

        allowed_actions = service_config.get("allowed_actions", [])

        return action_type in allowed_actions

    # -----------------------------------------------------------------------
    # Conflict handling and sorting
    # -----------------------------------------------------------------------

    @staticmethod
    def _remove_conflicts(
        actions: Sequence[RecoveryActionPlan],
    ) -> list[RecoveryActionPlan]:
        """
        Remove duplicate service/action pairs and conflicting actions.

        A service can have only one action of each type in a single plan.
        Additional conflict groups can be defined in recovery policies.
        """

        result: list[RecoveryActionPlan] = []
        seen: set[tuple[str, str]] = set()

        for action in actions:
            key = (action.service, action.action_type)

            if key in seen:
                continue

            seen.add(key)
            result.append(action)

        return result

    @staticmethod
    def _sort_actions(
        actions: Sequence[RecoveryActionPlan],
    ) -> list[RecoveryActionPlan]:
        priority_order = {
            ActionPriority.URGENT: 0,
            ActionPriority.HIGH: 1,
            ActionPriority.NORMAL: 2,
            ActionPriority.LOW: 3,
        }

        risk_order = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }

        return sorted(
            actions,
            key=lambda action: (
                priority_order[action.priority],
                risk_order[action.risk_level],
                action.service,
                action.action_type,
            ),
        )

    # -----------------------------------------------------------------------
    # Configuration loading and validation
    # -----------------------------------------------------------------------

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        if not path.exists():
            logger.warning(
                "Configuration file '%s' was not found.",
                path,
            )
            return {}

        try:
            with path.open("r", encoding="utf-8") as file:
                data = yaml.safe_load(file) or {}
        except yaml.YAMLError as exc:
            raise ValueError(
                f"Invalid YAML in '{path}': {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise ValueError(
                f"Configuration file '{path}' must contain a YAML mapping."
            )

        return data

    def _validate_configuration(self) -> None:
        actions = self.policies.get("actions", {})
        service_recovery = self.policies.get("service_recovery", {})
        services = self.dependencies.get("services", {})

        if not isinstance(actions, Mapping):
            raise ValueError(
                "'actions' in recovery_policies.yaml must be a mapping."
            )

        if not isinstance(service_recovery, Mapping):
            raise ValueError(
                "'service_recovery' must be a mapping."
            )

        if not isinstance(services, Mapping):
            raise ValueError(
                "'services' in service_dependencies.yaml must be a mapping."
            )

        execution = self.policies.get("execution", {})
        maximum_attempts = execution.get("maximum_attempts", 3)

        if not isinstance(maximum_attempts, int) or maximum_attempts < 1:
            raise ValueError(
                "'execution.maximum_attempts' must be a positive integer."
            )

    @staticmethod
    def _validate_assessment(
        assessment: IncidentAssessment,
    ) -> None:
        if not assessment.incident_id.strip():
            raise ValueError("incident_id cannot be empty.")

        if not assessment.service.strip():
            raise ValueError("service cannot be empty.")

        if not 0.0 <= assessment.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1.")

        if not 0.0 <= assessment.impact_score <= 100.0:
            raise ValueError("impact_score must be between 0 and 100.")

    @staticmethod
    def _normalize_text(value: str) -> str:
        return " ".join(str(value).strip().lower().split())

    @staticmethod
    def _utc_now() -> str:
        from datetime import datetime, timezone

        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------


def build_recovery_plan(
    assessment: IncidentAssessment,
    *,
    policy_path: str = "recovery_policies.yaml",
    dependency_path: str = "service_dependencies.yaml",
    requested_actions: Sequence[str] | None = None,
) -> RecoveryPlan:
    """
    Convenience function for use by main.py.

    Example:
        planner = RecoveryPlanner(
            policy_path="recovery_policies.yaml",
            dependency_path="service_dependencies.yaml",
        )
        plan = planner.create_plan(assessment)
        errors = planner.validate_plan(plan)
    """

    planner = RecoveryPlanner(
        policy_path=policy_path,
        dependency_path=dependency_path,
    )

    return planner.create_plan(
        assessment,
        requested_actions=requested_actions,
    )