"""
Incident detection engine for the Risk-Aware Recovery Controller.

Normalizes incoming monitoring signals, evaluates configurable detection
rules, correlates related symptoms, and produces structured incident records.

This module does not connect to a monitoring platform directly. Integrate
Prometheus, Alertmanager, or another monitoring source by passing normalized
signals to IncidentDetector.detect().
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence
from uuid import uuid4


class IncidentSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


@dataclass(frozen=True)
class MonitoringSignal:
    """A normalized signal received from a monitoring system."""

    service: str
    metric: str
    value: float | int | str | bool
    observed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    threshold: float | int | None = None
    labels: Mapping[str, str] = field(default_factory=dict)
    source: str = "unknown"
    message: str = ""

    def __post_init__(self) -> None:
        if not self.service.strip():
            raise ValueError("Signal service must not be empty.")

        if not self.metric.strip():
            raise ValueError("Signal metric must not be empty.")

        if self.observed_at.tzinfo is None:
            raise ValueError(
                "observed_at must be timezone-aware."
            )


@dataclass(frozen=True)
class DetectionRule:
    """A configurable rule for identifying an incident symptom."""

    name: str
    metric: str
    operator: str
    threshold: float
    symptom: str
    severity: IncidentSeverity = IncidentSeverity.WARNING
    description: str = ""
    enabled: bool = True

    def __post_init__(self) -> None:
        supported_operators = {">", ">=", "<", "<=", "==", "!="}

        if self.operator not in supported_operators:
            raise ValueError(
                f"Unsupported operator: {self.operator!r}"
            )

        if not self.name.strip():
            raise ValueError("Rule name must not be empty.")

        if not self.metric.strip():
            raise ValueError("Rule metric must not be empty.")


@dataclass(frozen=True)
class Incident:
    """Structured incident produced by the detector."""

    incident_id: str
    primary_service: str
    affected_services: tuple[str, ...]
    severity: IncidentSeverity
    symptoms: tuple[str, ...]
    suspected_causes: tuple[str, ...]
    signals: tuple[MonitoringSignal, ...]
    status: IncidentStatus
    detected_at: datetime
    summary: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the incident into a JSON-serializable dictionary."""
        return {
            "incident_id": self.incident_id,
            "primary_service": self.primary_service,
            "affected_services": list(self.affected_services),
            "severity": self.severity.value,
            "symptoms": list(self.symptoms),
            "suspected_causes": list(self.suspected_causes),
            "signals": [
                {
                    "service": signal.service,
                    "metric": signal.metric,
                    "value": signal.value,
                    "observed_at": signal.observed_at.isoformat(),
                    "threshold": signal.threshold,
                    "labels": dict(signal.labels),
                    "source": signal.source,
                    "message": signal.message,
                }
                for signal in self.signals
            ],
            "status": self.status.value,
            "detected_at": self.detected_at.isoformat(),
            "summary": self.summary,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class IncidentDetectorConfig:
    """Detection and correlation settings."""

    minimum_signals: int = 1
    correlation_window_seconds: int = 300
    default_severity: IncidentSeverity = IncidentSeverity.WARNING
    service_criticality: Mapping[str, str] = field(default_factory=dict)
    cause_mappings: Mapping[str, Sequence[str]] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if self.minimum_signals < 1:
            raise ValueError("minimum_signals must be at least 1.")

        if self.correlation_window_seconds < 0:
            raise ValueError(
                "correlation_window_seconds cannot be negative."
            )


class IncidentDetector:
    """
    Detect incidents from normalized monitoring signals.

    Detection consists of:
    1. Evaluating configured metric rules.
    2. Converting matching rules into symptoms.
    3. Correlating signals within a configurable time window.
    4. Creating a structured incident for the recovery planner.
    """

    _SEVERITY_ORDER = {
        IncidentSeverity.INFO: 0,
        IncidentSeverity.WARNING: 1,
        IncidentSeverity.ERROR: 2,
        IncidentSeverity.CRITICAL: 3,
    }

    def __init__(
        self,
        rules: Sequence[DetectionRule] | None = None,
        config: IncidentDetectorConfig | None = None,
    ) -> None:
        self.config = config or IncidentDetectorConfig()
        self.rules = tuple(rules or self.default_rules())

        self._validate_unique_rule_names()

    @staticmethod
    def default_rules() -> tuple[DetectionRule, ...]:
        """Return a conservative starter set of detection rules."""
        return (
            DetectionRule(
                name="high_cpu",
                metric="cpu_usage_percent",
                operator=">=",
                threshold=90,
                symptom="high_cpu",
                severity=IncidentSeverity.ERROR,
                description="CPU utilization reached the configured limit.",
            ),
            DetectionRule(
                name="high_memory",
                metric="memory_usage_percent",
                operator=">=",
                threshold=90,
                symptom="high_memory",
                severity=IncidentSeverity.ERROR,
                description="Memory utilization reached the configured limit.",
            ),
            DetectionRule(
                name="high_error_rate",
                metric="error_rate_percent",
                operator=">=",
                threshold=5,
                symptom="high_error_rate",
                severity=IncidentSeverity.ERROR,
                description="Error rate reached the configured limit.",
            ),
            DetectionRule(
                name="high_latency",
                metric="latency_ms",
                operator=">=",
                threshold=1000,
                symptom="high_latency",
                severity=IncidentSeverity.WARNING,
                description="Request latency reached the configured limit.",
            ),
            DetectionRule(
                name="service_unhealthy",
                metric="health_status",
                operator="==",
                threshold=0,
                symptom="service_unhealthy",
                severity=IncidentSeverity.CRITICAL,
                description="The service health check reported unhealthy.",
            ),
        )

    def detect(
        self,
        signals: Sequence[MonitoringSignal],
        *,
        primary_service: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Incident | None:
        """
        Detect an incident from a batch of monitoring signals.

        Returns None when no configured rule matches or when too few
        matching signals are present.
        """
        if not signals:
            return None

        matching: list[
            tuple[MonitoringSignal, DetectionRule]
        ] = []

        for signal in signals:
            rule = self._find_matching_rule(signal)
            if rule is not None:
                matching.append((signal, rule))

        if len(matching) < self.config.minimum_signals:
            return None

        correlated = self._correlate(matching)
        if not correlated:
            return None

        services = sorted(
            {signal.service for signal, _ in correlated}
        )

        selected_primary = (
            primary_service
            if primary_service in services
            else self._select_primary_service(services)
        )

        symptoms = tuple(
            sorted({rule.symptom for _, rule in correlated})
        )

        severity = max(
            (rule.severity for _, rule in correlated),
            key=lambda level: self._SEVERITY_ORDER[level],
        )

        causes = self._infer_suspected_causes(symptoms)

        incident_signals = tuple(
            signal for signal, _ in correlated
        )

        detected_at = datetime.now(timezone.utc)

        return Incident(
            incident_id=f"inc-{uuid4().hex[:12]}",
            primary_service=selected_primary,
            affected_services=tuple(services),
            severity=severity,
            symptoms=symptoms,
            suspected_causes=causes,
            signals=incident_signals,
            status=IncidentStatus.OPEN,
            detected_at=detected_at,
            summary=self._build_summary(
                selected_primary,
                severity,
                symptoms,
                services,
            ),
            metadata=dict(metadata or {}),
        )

    def detect_many(
        self,
        signal_batches: Sequence[Sequence[MonitoringSignal]],
    ) -> list[Incident]:
        """Detect incidents independently for multiple signal batches."""
        incidents: list[Incident] = []

        for batch in signal_batches:
            incident = self.detect(batch)
            if incident is not None:
                incidents.append(incident)

        return incidents

    def _find_matching_rule(
        self,
        signal: MonitoringSignal,
    ) -> DetectionRule | None:
        for rule in self.rules:
            if not rule.enabled or rule.metric != signal.metric:
                continue

            if self._matches(signal.value, rule):
                return rule

        return None

    @staticmethod
    def _matches(
        value: float | int | str | bool,
        rule: DetectionRule,
    ) -> bool:
        """
        Evaluate a rule safely.

        Health metrics may be reported as strings such as 'healthy' or
        'unhealthy'. Numeric comparisons reject incompatible input.
        """
        if rule.operator in {"==", "!="}:
            expected: Any = rule.threshold

            if isinstance(value, str):
                normalized = value.strip().lower()

                if normalized in {"healthy", "up", "ok", "true"}:
                    normalized_value: Any = 1
                elif normalized in {
                    "unhealthy",
                    "down",
                    "failed",
                    "false",
                }:
                    normalized_value = 0
                else:
                    try:
                        normalized_value = float(normalized)
                    except ValueError:
                        normalized_value = normalized

                value = normalized_value

            if rule.operator == "==":
                return value == expected
            return value != expected

        try:
            numeric_value = float(value)
        except (TypeError, ValueError):
            return False

        if rule.operator == ">":
            return numeric_value > rule.threshold
        if rule.operator == ">=":
            return numeric_value >= rule.threshold
        if rule.operator == "<":
            return numeric_value < rule.threshold
        if rule.operator == "<=":
            return numeric_value <= rule.threshold

        return False

    def _correlate(
        self,
        matches: Sequence[
            tuple[MonitoringSignal, DetectionRule]
        ],
    ) -> list[tuple[MonitoringSignal, DetectionRule]]:
        """
        Retain signals within the configured time window.

        Signals are compared against the newest matching signal. This keeps
        old alerts from being combined with unrelated new incidents.
        """
        if not matches:
            return []

        newest = max(
            signal.observed_at for signal, _ in matches
        )

        window_seconds = self.config.correlation_window_seconds

        return [
            (signal, rule)
            for signal, rule in matches
            if 0
            <= (newest - signal.observed_at).total_seconds()
            <= window_seconds
        ]

    def _infer_suspected_causes(
        self,
        symptoms: Sequence[str],
    ) -> tuple[str, ...]:
        causes: set[str] = set()

        for symptom in symptoms:
            mapped_causes = self.config.cause_mappings.get(
                symptom,
                (),
            )
            causes.update(mapped_causes)

        return tuple(sorted(causes))

    def _select_primary_service(
        self,
        services: Sequence[str],
    ) -> str:
        """Select the most critical affected service when configured."""
        criticality_rank = {
            "low": 0,
            "medium": 1,
            "high": 2,
            "critical": 3,
        }

        return max(
            services,
            key=lambda service: criticality_rank.get(
                self.config.service_criticality.get(
                    service, "medium"
                ).lower(),
                1,
            ),
        )

    @staticmethod
    def _build_summary(
        primary_service: str,
        severity: IncidentSeverity,
        symptoms: Sequence[str],
        services: Sequence[str],
    ) -> str:
        symptom_text = ", ".join(symptoms)
        service_text = ", ".join(services)

        return (
            f"{severity.value.upper()} incident detected for "
            f"{primary_service}. Symptoms: {symptom_text}. "
            f"Affected services: {service_text}."
        )

    def _validate_unique_rule_names(self) -> None:
        names = [rule.name for rule in self.rules]

        if len(names) != len(set(names)):
            raise ValueError(
                "Detection rule names must be unique."
            )


def build_default_detector() -> IncidentDetector:
    """Build a detector with default rules and cause mappings."""
    config = IncidentDetectorConfig(
        service_criticality={
            "api": "critical",
            "database": "critical",
            "worker": "medium",
            "cache": "high",
        },
        cause_mappings={
            "high_cpu": ("resource_exhaustion",),
            "high_memory": ("resource_exhaustion",),
            "high_error_rate": ("application_failure",),
            "high_latency": ("performance_degradation",),
            "service_unhealthy": ("service_failure",),
        },
    )

    return IncidentDetector(config=config)


if __name__ == "__main__":
    detector = build_default_detector()
    now = datetime.now(timezone.utc)

    sample_signals = [
        MonitoringSignal(
            service="api",
            metric="cpu_usage_percent",
            value=96,
            observed_at=now,
            source="demo",
            message="CPU usage exceeded threshold",
        ),
        MonitoringSignal(
            service="api",
            metric="health_status",
            value="unhealthy",
            observed_at=now,
            source="demo",
            message="Health check failed",
        ),
        MonitoringSignal(
            service="worker",
            metric="error_rate_percent",
            value=8,
            observed_at=now,
            source="demo",
            message="Elevated application error rate",
        ),
    ]

    incident = detector.detect(
        sample_signals,
        primary_service="api",
        metadata={"environment": "development"},
    )

    if incident is None:
        print("No incident detected.")
    else:
        print("Detected incident:")
        print(incident.to_dict())