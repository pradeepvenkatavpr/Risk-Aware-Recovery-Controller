"""
Risk assessment engine for the Risk-Aware Recovery Controller.

Evaluates incident severity, service criticality, blast radius, data-loss
potential, and recovery-action risk before a recovery plan is executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RiskAssessment:
    """Immutable result of an incident or recovery-action risk assessment."""

    risk_level: RiskLevel
    risk_score: int
    factors: Mapping[str, int]
    reasons: tuple[str, ...]
    requires_approval: bool
    execution_allowed: bool
    recommended_mode: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "factors": dict(self.factors),
            "reasons": list(self.reasons),
            "requires_approval": self.requires_approval,
            "execution_allowed": self.execution_allowed,
            "recommended_mode": self.recommended_mode,
        }


@dataclass(frozen=True)
class RiskAssessorConfig:
    """Thresholds and safety limits for risk scoring."""

    low_max_score: int = 24
    medium_max_score: int = 49
    high_max_score: int = 74

    approval_required_levels: frozenset[RiskLevel] = frozenset(
        {RiskLevel.HIGH, RiskLevel.CRITICAL}
    )

    maximum_planned_risk: RiskLevel = RiskLevel.CRITICAL

    # Fail-closed controls for potentially destructive operations.
    require_approval_for_data_loss: bool = True
    require_approval_for_critical_services: bool = True
    block_unknown_action_risk: bool = True

    def __post_init__(self) -> None:
        thresholds = (
            self.low_max_score,
            self.medium_max_score,
            self.high_max_score,
        )

        if any(not 0 <= value <= 100 for value in thresholds):
            raise ValueError("Risk thresholds must be between 0 and 100.")

        if not (
            self.low_max_score
            < self.medium_max_score
            < self.high_max_score
        ):
            raise ValueError(
                "Risk thresholds must increase from low to high."
            )


class RiskAssessor:
    """
    Calculate risk scores and recommend safe recovery execution settings.

    Inputs are expected to come from the incident detector, service metadata,
    recovery planner, and configured recovery policies.
    """

    _RISK_ORDER = {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 2,
        RiskLevel.CRITICAL: 3,
    }

    _SEVERITY_POINTS = {
        IncidentSeverity.INFO: 5,
        IncidentSeverity.WARNING: 15,
        IncidentSeverity.ERROR: 25,
        IncidentSeverity.CRITICAL: 35,
    }

    _CRITICALITY_POINTS = {
        "low": 5,
        "medium": 12,
        "high": 20,
        "critical": 30,
    }

    _ACTION_RISK_POINTS = {
        RiskLevel.LOW: 5,
        RiskLevel.MEDIUM: 15,
        RiskLevel.HIGH: 25,
        RiskLevel.CRITICAL: 35,
    }

    def __init__(
        self,
        config: RiskAssessorConfig | None = None,
    ) -> None:
        self.config = config or RiskAssessorConfig()

    def assess_incident(
        self,
        *,
        severity: str | IncidentSeverity,
        service_criticality: str = "medium",
        affected_service_count: int = 1,
        total_service_count: int = 1,
        data_loss_possible: bool = False,
        customer_impact: bool = False,
        production_environment: bool = True,
        signals: Sequence[str] | None = None,
    ) -> RiskAssessment:
        """
        Assess incident risk using severity and operational impact.

        `affected_service_count` and `total_service_count` describe the
        observed blast radius. Invalid counts are rejected rather than
        silently normalized.
        """
        normalized_severity = self._parse_severity(severity)
        normalized_criticality = service_criticality.strip().lower()

        if normalized_criticality not in self._CRITICALITY_POINTS:
            raise ValueError(
                f"Unknown service criticality: {service_criticality!r}"
            )

        if affected_service_count < 0:
            raise ValueError("affected_service_count cannot be negative.")

        if total_service_count < 1:
            raise ValueError("total_service_count must be at least 1.")

        if affected_service_count > total_service_count:
            raise ValueError(
                "affected_service_count cannot exceed total_service_count."
            )

        factors: dict[str, int] = {
            "incident_severity": self._SEVERITY_POINTS[
                normalized_severity
            ],
            "service_criticality": self._CRITICALITY_POINTS[
                normalized_criticality
            ],
            "blast_radius": self._blast_radius_points(
                affected_service_count,
                total_service_count,
            ),
            "data_loss": 25 if data_loss_possible else 0,
            "customer_impact": 15 if customer_impact else 0,
            "production_environment": 10 if production_environment else 0,
        }

        reasons = [
            f"Incident severity is {normalized_severity.value}.",
            f"Service criticality is {normalized_criticality}.",
            (
                f"{affected_service_count} of {total_service_count} "
                "services are affected."
            ),
        ]

        if data_loss_possible:
            reasons.append("Potential data loss increases operational risk.")

        if customer_impact:
            reasons.append("Customer impact has been reported.")

        if production_environment:
            reasons.append("The incident affects a production environment.")

        for signal in signals or ():
            reasons.append(f"Incident signal: {signal}")

        return self._build_assessment(
            factors=factors,
            reasons=reasons,
            force_approval=(
                data_loss_possible
                and self.config.require_approval_for_data_loss
            )
            or (
                normalized_criticality == "critical"
                and self.config.require_approval_for_critical_services
            ),
            block_execution=False,
        )

    def assess_recovery_action(
        self,
        *,
        action_type: str,
        action_risk: str | RiskLevel | None,
        service_criticality: str = "medium",
        affects_multiple_services: bool = False,
        data_loss_possible: bool = False,
        rollback_available: bool = True,
        production_environment: bool = True,
        parameters: Mapping[str, Any] | None = None,
    ) -> RiskAssessment:
        """
        Assess the risk of a proposed recovery action.

        Unknown action risk can be blocked by configuration. A rollback
        reduces the score but never makes a destructive action automatically
        safe.
        """
        if not action_type or not action_type.strip():
            raise ValueError("action_type must not be empty.")

        criticality = service_criticality.strip().lower()
        if criticality not in self._CRITICALITY_POINTS:
            raise ValueError(
                f"Unknown service criticality: {service_criticality!r}"
            )

        factors: dict[str, int] = {
            "service_criticality": self._CRITICALITY_POINTS[criticality],
            "multi_service_impact": 15 if affects_multiple_services else 0,
            "data_loss": 30 if data_loss_possible else 0,
            "production_environment": 10 if production_environment else 0,
            "rollback_unavailable": 0 if rollback_available else 10,
        }

        reasons = [f"Proposed recovery action: {action_type}."]

        block_execution = False
        force_approval = False

        try:
            normalized_action_risk = self._parse_risk(action_risk)
        except ValueError:
            if self.config.block_unknown_action_risk:
                normalized_action_risk = RiskLevel.CRITICAL
                block_execution = True
                force_approval = True
                reasons.append(
                    "Action risk is unknown; execution is blocked by policy."
                )
            else:
                normalized_action_risk = RiskLevel.MEDIUM
                reasons.append(
                    "Unknown action risk was conservatively treated as medium."
                )

        factors["action_risk"] = self._ACTION_RISK_POINTS[
            normalized_action_risk
        ]

        reasons.append(
            f"Configured action risk is {normalized_action_risk.value}."
        )

        if affects_multiple_services:
            reasons.append(
                "The action may affect multiple services."
            )

        if data_loss_possible:
            reasons.append(
                "The action may cause data loss or irreversible changes."
            )
            force_approval = (
                force_approval
                or self.config.require_approval_for_data_loss
            )

        if not rollback_available:
            reasons.append(
                "No rollback is available for this action."
            )

        if criticality == "critical":
            force_approval = (
                force_approval
                or self.config.require_approval_for_critical_services
            )

        if parameters and parameters.get("destructive") is True:
            force_approval = True
            reasons.append(
                "Action parameters explicitly mark this action as destructive."
            )

        return self._build_assessment(
            factors=factors,
            reasons=reasons,
            force_approval=force_approval,
            block_execution=block_execution,
        )

    def combine_assessments(
        self,
        assessments: Sequence[RiskAssessment],
    ) -> RiskAssessment:
        """
        Combine assessments conservatively for a multi-action recovery plan.

        The highest individual risk level is retained as a minimum risk
        classification, while scores and approval requirements are combined.
        """
        if not assessments:
            raise ValueError(
                "At least one assessment is required to combine risk."
            )

        combined_factors: dict[str, int] = {}
        reasons: list[str] = []

        for index, assessment in enumerate(assessments, start=1):
            for name, value in assessment.factors.items():
                key = f"item_{index}.{name}"
                combined_factors[key] = value

            reasons.extend(
                f"Assessment {index}: {reason}"
                for reason in assessment.reasons
            )

        # Use the maximum score rather than summing scores, since scores
        # are normalized to 0–100 and summing would distort their meaning.
        highest_score = max(item.risk_score for item in assessments)
        highest_level = max(
            (item.risk_level for item in assessments),
            key=lambda level: self._RISK_ORDER[level],
        )

        combined = self._build_assessment(
            factors={"combined_max_score": highest_score},
            reasons=reasons,
            force_approval=any(
                item.requires_approval for item in assessments
            ),
            block_execution=any(
                not item.execution_allowed for item in assessments
            ),
        )

        # Do not let recomputing the score lower the highest assessment's
        # risk classification.
        final_level = max(
            (combined.risk_level, highest_level),
            key=lambda level: self._RISK_ORDER[level],
        )

        return RiskAssessment(
            risk_level=final_level,
            risk_score=max(combined.risk_score, highest_score),
            factors=combined_factors,
            reasons=tuple(reasons),
            requires_approval=combined.requires_approval
            or any(item.requires_approval for item in assessments)
            or final_level in self.config.approval_required_levels,
            execution_allowed=combined.execution_allowed
            and all(item.execution_allowed for item in assessments),
            recommended_mode=(
                "blocked"
                if not combined.execution_allowed
                or any(not item.execution_allowed for item in assessments)
                else "dry_run"
                if final_level in {
                    RiskLevel.HIGH,
                    RiskLevel.CRITICAL,
                }
                else "controlled"
            ),
        )

    def _build_assessment(
        self,
        *,
        factors: Mapping[str, int],
        reasons: Sequence[str],
        force_approval: bool,
        block_execution: bool,
    ) -> RiskAssessment:
        score = min(100, max(0, sum(factors.values())))
        risk_level = self._score_to_level(score)

        requires_approval = (
            force_approval
            or risk_level in self.config.approval_required_levels
        )

        maximum_level = self.config.maximum_planned_risk
        exceeds_maximum = (
            self._RISK_ORDER[risk_level]
            > self._RISK_ORDER[maximum_level]
        )

        execution_allowed = not block_execution and not exceeds_maximum

        if block_execution:
            recommended_mode = "blocked"
        elif not execution_allowed:
            recommended_mode = "blocked"
        elif risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            recommended_mode = "dry_run"
        else:
            recommended_mode = "controlled"

        if exceeds_maximum:
            reasons = [
                *reasons,
                (
                    f"Risk level {risk_level.value} exceeds configured "
                    f"maximum {maximum_level.value}."
                ),
            ]

        if requires_approval:
            reasons = [
                *reasons,
                "Human approval is required before live execution.",
            ]

        return RiskAssessment(
            risk_level=risk_level,
            risk_score=score,
            factors=dict(factors),
            reasons=tuple(reasons),
            requires_approval=requires_approval,
            execution_allowed=execution_allowed,
            recommended_mode=recommended_mode,
        )

    def _score_to_level(self, score: int) -> RiskLevel:
        if score <= self.config.low_max_score:
            return RiskLevel.LOW
        if score <= self.config.medium_max_score:
            return RiskLevel.MEDIUM
        if score <= self.config.high_max_score:
            return RiskLevel.HIGH
        return RiskLevel.CRITICAL

    @staticmethod
    def _blast_radius_points(
        affected_service_count: int,
        total_service_count: int,
    ) -> int:
        if affected_service_count == 0:
            return 0

        ratio = affected_service_count / total_service_count

        if affected_service_count >= 5 or ratio >= 0.75:
            return 20
        if affected_service_count >= 3 or ratio >= 0.50:
            return 15
        if affected_service_count >= 2 or ratio >= 0.25:
            return 10
        return 5

    @staticmethod
    def _parse_risk(
        value: str | RiskLevel | None,
    ) -> RiskLevel:
        if isinstance(value, RiskLevel):
            return value

        if isinstance(value, str):
            try:
                return RiskLevel(value.strip().lower())
            except ValueError as exc:
                raise ValueError(
                    f"Unsupported risk level: {value!r}"
                ) from exc

        raise ValueError("Action risk level is missing or invalid.")

    @staticmethod
    def _parse_severity(
        value: str | IncidentSeverity,
    ) -> IncidentSeverity:
        if isinstance(value, IncidentSeverity):
            return value

        if isinstance(value, str):
            try:
                return IncidentSeverity(value.strip().lower())
            except ValueError as exc:
                raise ValueError(
                    f"Unsupported incident severity: {value!r}"
                ) from exc

        raise ValueError("Incident severity is missing or invalid.")


def build_risk_assessor(
    policy: Mapping[str, Any] | None = None,
) -> RiskAssessor:
    """
    Construct a RiskAssessor using the risk section of recovery policies.

    Example:
        assessor = build_risk_assessor({
            "approval_required_levels": ["high", "critical"],
            "maximum_planned_risk": "critical",
        })
    """
    policy = policy or {}

    approval_levels_raw = policy.get(
        "approval_required_levels",
        ["high", "critical"],
    )

    approval_levels = frozenset(
        RiskLevel(str(level).strip().lower())
        for level in approval_levels_raw
    )

    maximum_risk = RiskLevel(
        str(
            policy.get("maximum_planned_risk", "critical")
        ).strip().lower()
    )

    config = RiskAssessorConfig(
        low_max_score=int(policy.get("low_max_score", 24)),
        medium_max_score=int(policy.get("medium_max_score", 49)),
        high_max_score=int(policy.get("high_max_score", 74)),
        approval_required_levels=approval_levels,
        maximum_planned_risk=maximum_risk,
        require_approval_for_data_loss=bool(
            policy.get("require_approval_for_data_loss", True)
        ),
        require_approval_for_critical_services=bool(
            policy.get("require_approval_for_critical_services", True)
        ),
        block_unknown_action_risk=bool(
            policy.get("block_unknown_action_risk", True)
        ),
    )

    return RiskAssessor(config)


if __name__ == "__main__":
    assessor = build_risk_assessor()

    incident = assessor.assess_incident(
        severity=IncidentSeverity.ERROR,
        service_criticality="high",
        affected_service_count=2,
        total_service_count=5,
        data_loss_possible=False,
        customer_impact=True,
        production_environment=True,
        signals=["service_unhealthy", "elevated_error_rate"],
    )

    print("Incident risk assessment:")
    print(incident.to_dict())

    action = assessor.assess_recovery_action(
        action_type="restart_service",
        action_risk=RiskLevel.MEDIUM,
        service_criticality="high",
        affects_multiple_services=False,
        data_loss_possible=False,
        rollback_available=True,
        production_environment=True,
    )

    print("\nRecovery action risk assessment:")
    print(action.to_dict())