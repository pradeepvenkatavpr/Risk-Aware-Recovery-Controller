"""
Risk-Aware Recovery Controller
Production Reliability + Controlled Automation

Application entry point that connects:
- Incident detection
- Risk assessment
- Recovery planning
- Controlled recovery execution

Safety defaults:
- DRY_RUN mode is enabled by default.
- LIVE execution requires explicit configuration.
- High-risk actions require approval.
- Unknown actions are rejected.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from incident_detector import (
    Incident,
    IncidentDetector,
    IncidentDetectorConfig,
    MonitoringSignal,
)
from recovery_executor import (
    ExecutionMode,
    RecoveryAction,
    RecoveryExecutor,
    RiskLevel as ExecutorRiskLevel,
)
from recovery_planner import (
    IncidentAssessment,
    RecoveryPlanner,
)
from risk_assessor import (
    RiskAssessor,
    RiskLevel,
)


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.yaml"
DEFAULT_POLICIES_PATH = BASE_DIR / "recovery_policies.yaml"
DEFAULT_DEPENDENCIES_PATH = BASE_DIR / "service_dependencies.yaml"

LOGGER = logging.getLogger("recovery_controller")


class ConfigurationError(RuntimeError):
    """Raised when application configuration is invalid."""


class RecoveryController:
    """Coordinates incident detection, risk assessment, planning, and execution."""

    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        policies: Mapping[str, Any],
        dependencies: Mapping[str, Any],
    ) -> None:
        self.config = dict(config)
        self.policies = dict(policies)
        self.dependencies = dict(dependencies)

        self.detector = self._build_detector()
        self.risk_assessor = self._build_risk_assessor()
        self.planner = RecoveryPlanner(
            policies=self.policies,
            dependencies=self.dependencies,
        )
        self.executor = self._build_executor()

    def _build_detector(self) -> IncidentDetector:
        detector_config = self.config.get("incident_detection", {})
        detector_config = (
            detector_config
            if isinstance(detector_config, Mapping)
            else {}
        )

        rules = None
        raw_rules = detector_config.get("rules")

        if isinstance(raw_rules, list):
            from incident_detector import (
                DetectionRule,
                IncidentSeverity,
            )

            rules = []

            for raw in raw_rules:
                if not isinstance(raw, Mapping):
                    raise ConfigurationError(
                        "Each incident detection rule must be a mapping."
                    )

                try:
                    rules.append(
                        DetectionRule(
                            name=str(raw["name"]),
                            metric=str(raw["metric"]),
                            operator=str(raw["operator"]),
                            threshold=float(raw["threshold"]),
                            symptom=str(raw["symptom"]),
                            severity=IncidentSeverity(
                                str(
                                    raw.get("severity", "warning")
                                ).lower()
                            ),
                            description=str(
                                raw.get("description", "")
                            ),
                            enabled=bool(raw.get("enabled", True)),
                        )
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise ConfigurationError(
                        f"Invalid incident detection rule: {raw!r}"
                    ) from exc

        config = IncidentDetectorConfig(
            minimum_signals=int(
                detector_config.get("minimum_signals", 1)
            ),
            correlation_window_seconds=int(
                detector_config.get(
                    "correlation_window_seconds",
                    300,
                )
            ),
            service_criticality=self.config.get(
                "service_criticality",
                {},
            ),
            cause_mappings=detector_config.get(
                "cause_mappings",
                {},
            ),
        )

        return IncidentDetector(rules=rules, config=config)

    def _build_risk_assessor(self) -> RiskAssessor:
        risk_policy = self.policies.get("risk", {})
        if not isinstance(risk_policy, Mapping):
            raise ConfigurationError(
                "The 'risk' section in recovery_policies.yaml must be a mapping."
            )

        return RiskAssessor.from_policy(risk_policy) if hasattr(
            RiskAssessor, "from_policy"
        ) else self._build_risk_assessor_compat(risk_policy)

    @staticmethod
    def _build_risk_assessor_compat(
        risk_policy: Mapping[str, Any],
    ) -> RiskAssessor:
        """Build the assessor using the project's public factory."""
        from risk_assessor import build_risk_assessor

        return build_risk_assessor(risk_policy)

    def _build_executor(self) -> RecoveryExecutor:
        execution_config = self.config.get("execution", {})
        execution_config = (
            execution_config
            if isinstance(execution_config, Mapping)
            else {}
        )

        requested_mode = os.getenv(
            "RECOVERY_EXECUTION_MODE",
            str(execution_config.get("mode", "dry_run")),
        ).strip().lower()

        if requested_mode not in {"dry_run", "live"}:
            raise ConfigurationError(
                "RECOVERY_EXECUTION_MODE must be 'dry_run' or 'live'."
            )

        # Live mode must be explicitly enabled in both configuration and
        # environment to reduce the chance of accidental production actions.
        live_enabled = (
            requested_mode == "live"
            and bool(execution_config.get("allow_live_execution", False))
            and os.getenv("ALLOW_LIVE_RECOVERY", "").strip().lower()
            == "true"
        )

        mode = (
            ExecutionMode.LIVE
            if live_enabled
            else ExecutionMode.DRY_RUN
        )

        if requested_mode == "live" and not live_enabled:
            LOGGER.warning(
                "Live mode requested, but explicit live safeguards "
                "are not satisfied. Falling back to DRY_RUN."
            )

        allowed_actions = self._allowed_actions()

        return RecoveryExecutor(
            mode=mode,
            allowed_actions=allowed_actions,
            require_approval_for_risk_levels={
                ExecutorRiskLevel.HIGH,
                ExecutorRiskLevel.CRITICAL,
            },
            audit_log_path=str(
                execution_config.get(
                    "audit_log_path",
                    BASE_DIR / "recovery_audit.jsonl",
                )
            ),
        )

    def _allowed_actions(self) -> set[str]:
        """Build the action allowlist from enabled recovery policies."""
        actions = self.policies.get("actions", {})

        if not isinstance(actions, Mapping):
            raise ConfigurationError(
                "'actions' in recovery_policies.yaml must be a mapping."
            )

        return {
            str(action_name)
            for action_name, settings in actions.items()
            if isinstance(settings, Mapping)
            and settings.get("enabled", False) is True
        }

    async def process_signals(
        self,
        signals: list[MonitoringSignal],
    ) -> dict[str, Any]:
        """Run one batch of signals through the complete recovery pipeline."""
        if not signals:
            return {
                "status": "no_signals",
                "incident": None,
                "risk": None,
                "plan": None,
                "execution_results": [],
            }

        incident = self.detector.detect(signals)

        if incident is None:
            LOGGER.info("No incident matched the configured detection rules.")
            return {
                "status": "no_incident",
                "incident": None,
                "risk": None,
                "plan": None,
                "execution_results": [],
            }

        LOGGER.warning(
            "Incident detected: id=%s severity=%s service=%s",
            incident.incident_id,
            incident.severity.value,
            incident.primary_service,
        )

        incident_risk = self.risk_assessor.assess_incident(
            severity=incident.severity.value,
            service_criticality=self._service_criticality(
                incident.primary_service
            ),
            affected_service_count=len(incident.affected_services),
            total_service_count=max(
                len(self.dependencies.get("services", {})),
                len(incident.affected_services),
                1,
            ),
            data_loss_possible=bool(
                incident.metadata.get("data_loss_possible", False)
            ),
            customer_impact=bool(
                incident.metadata.get("customer_impact", False)
            ),
            production_environment=self._is_production(),
            signals=incident.symptoms,
        )

        incident_assessment = self._to_planner_assessment(
            incident,
            incident_risk,
        )

        plan = self.planner.create_plan(incident_assessment)

        plan_validation = self.planner.validate_plan(plan)

        if not plan_validation:
            LOGGER.error(
                "Recovery plan failed validation for incident %s",
                incident.incident_id,
            )
            return {
                "status": "plan_rejected",
                "incident": incident.to_dict(),
                "risk": incident_risk.to_dict(),
                "plan": self._serialize(plan),
                "execution_results": [],
            }

        # The risk assessor is authoritative: an assessment that blocks
        # execution must never proceed to live recovery.
        if not incident_risk.execution_allowed:
            LOGGER.warning(
                "Recovery blocked by incident risk policy: %s",
                incident.incident_id,
            )
            return {
                "status": "risk_blocked",
                "incident": incident.to_dict(),
                "risk": incident_risk.to_dict(),
                "plan": self._serialize(plan),
                "execution_results": [],
            }

        if incident_risk.requires_approval:
            LOGGER.warning(
                "Recovery requires human approval: %s",
                incident.incident_id,
            )
            return {
                "status": "approval_required",
                "incident": incident.to_dict(),
                "risk": incident_risk.to_dict(),
                "plan": self._serialize(plan),
                "execution_results": [],
            }

        if incident_risk.recommended_mode == "dry_run":
            LOGGER.warning(
                "Risk assessment recommends DRY_RUN; live execution skipped."
            )
            return {
                "status": "dry_run_recommended",
                "incident": incident.to_dict(),
                "risk": incident_risk.to_dict(),
                "plan": self._serialize(plan),
                "execution_results": [],
            }

        execution_results: list[dict[str, Any]] = []

        for planned_action in getattr(plan, "actions", []):
            executor_action = self._to_executor_action(
                planned_action,
                incident,
            )

            result = await self.executor.execute(executor_action)
            serialized_result = self._serialize(result)
            execution_results.append(serialized_result)

            if not self._execution_succeeded(result):
                LOGGER.error(
                    "Recovery action failed or was blocked: incident=%s action=%s",
                    incident.incident_id,
                    getattr(planned_action, "action_type", "unknown"),
                )
                break

        return {
            "status": "completed",
            "incident": incident.to_dict(),
            "risk": incident_risk.to_dict(),
            "plan": self._serialize(plan),
            "execution_results": execution_results,
        }

    def _to_planner_assessment(
        self,
        incident: Incident,
        risk: Any,
    ) -> IncidentAssessment:
        """Map detected incident and risk information into planner inputs."""
        fields = getattr(
            IncidentAssessment,
            "__dataclass_fields__",
            {},
        )

        candidates: dict[str, Any] = {
            "incident_id": incident.incident_id,
            "primary_service": incident.primary_service,
            "affected_services": list(incident.affected_services),
            "severity": incident.severity.value,
            "symptoms": list(incident.symptoms),
            "suspected_causes": list(incident.suspected_causes),
            "risk_level": risk.risk_level.value,
            "risk_score": risk.risk_score,
            "requires_approval": risk.requires_approval,
            "metadata": dict(incident.metadata),
        }

        accepted = {
            key: value
            for key, value in candidates.items()
            if key in fields
        }

        try:
            return IncidentAssessment(**accepted)
        except TypeError as exc:
            raise ConfigurationError(
                "IncidentAssessment fields do not match the controller "
                "integration. Check recovery_planner.py."
            ) from exc

    def _to_executor_action(
        self,
        planned_action: Any,
        incident: Incident,
    ) -> RecoveryAction:
        """Translate a planner action into the executor's action model."""
        action_type = getattr(
            planned_action,
            "action_type",
            getattr(planned_action, "name", None),
        )

        if not action_type:
            raise ConfigurationError(
                "Planned recovery action has no action_type or name."
            )

        action_config = self.policies.get("actions", {}).get(
            action_type,
            {},
        )

        if not isinstance(action_config, Mapping):
            raise ConfigurationError(
                f"Invalid configuration for action {action_type!r}."
            )

        raw_risk = getattr(
            planned_action,
            "risk_level",
            action_config.get("risk_level", "high"),
        )

        executor_risk = ExecutorRiskLevel(
            str(
                getattr(raw_risk, "value", raw_risk)
            ).lower()
        )

        parameters = getattr(
            planned_action,
            "parameters",
            action_config.get("parameters", {}),
        )

        if not isinstance(parameters, Mapping):
            parameters = {}

        return RecoveryAction(
            action_type=str(action_type),
            service=incident.primary_service,
            parameters=dict(parameters),
            risk_level=executor_risk,
            requires_approval=bool(
                getattr(
                    planned_action,
                    "requires_approval",
                    action_config.get("requires_approval", False),
                )
            ),
            approved=bool(getattr(planned_action, "approved", False)),
            approval_reference=getattr(
                planned_action,
                "approval_reference",
                None,
            ),
            timeout_seconds=int(
                getattr(
                    planned_action,
                    "timeout_seconds",
                    action_config.get("timeout_seconds", 30),
                )
            ),
            max_attempts=int(
                getattr(
                    planned_action,
                    "max_attempts",
                    action_config.get("max_attempts", 1),
                )
            ),
            rollback_action_type=action_config.get(
                "rollback_action_type"
            ),
            incident_id=incident.incident_id,
        )

    def _service_criticality(self, service: str) -> str:
        criticality = self.config.get("service_criticality", {})
        if not isinstance(criticality, Mapping):
            return "medium"

        return str(criticality.get(service, "medium")).lower()

    def _is_production(self) -> bool:
        environment = os.getenv(
            "APP_ENV",
            str(self.config.get("environment", "development")),
        ).strip().lower()

        return environment in {"prod", "production"}

    @staticmethod
    def _execution_succeeded(result: Any) -> bool:
        status = getattr(result, "status", None)

        if status is None:
            return bool(getattr(result, "success", False))

        status_value = str(getattr(status, "value", status)).lower()
        return status_value in {"success", "succeeded", "completed"}

    @staticmethod
    def _serialize(value: Any) -> Any:
        if hasattr(value, "to_dict"):
            return value.to_dict()

        if hasattr(value, "__dataclass_fields__"):
            from dataclasses import asdict

            return asdict(value)

        if isinstance(value, EnumLike):
            return value.value

        if isinstance(value, Mapping):
            return {
                str(key): RecoveryController._serialize(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple)):
            return [
                RecoveryController._serialize(item)
                for item in value
            ]

        if hasattr(value, "value") and isinstance(
            getattr(value, "value"),
            (str, int, float, bool),
        ):
            return value.value

        return value


# Used only for safe serialization of enum-like values.
class EnumLike:
    value: Any


def load_yaml_file(path: Path) -> dict[str, Any]:
    """Load a YAML mapping from disk with explicit error reporting."""
    if not path.is_file():
        raise ConfigurationError(f"Configuration file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as handle:
            content = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"Invalid YAML in {path.name}: {exc}"
        ) from exc
    except OSError as exc:
        raise ConfigurationError(
            f"Could not read {path}: {exc}"
        ) from exc

    if not isinstance(content, dict):
        raise ConfigurationError(
            f"{path.name} must contain a YAML mapping."
        )

    return content


def load_controller() -> RecoveryController:
    """Load application configuration and construct the controller."""
    config_path = Path(
        os.getenv("RECOVERY_CONFIG", str(DEFAULT_CONFIG_PATH))
    )
    policies_path = Path(
        os.getenv("RECOVERY_POLICIES", str(DEFAULT_POLICIES_PATH))
    )
    dependencies_path = Path(
        os.getenv(
            "SERVICE_DEPENDENCIES",
            str(DEFAULT_DEPENDENCIES_PATH),
        )
    )

    config = load_yaml_file(config_path)
    policies = load_yaml_file(policies_path)
    dependencies = load_yaml_file(dependencies_path)

    return RecoveryController(
        config=config,
        policies=policies,
        dependencies=dependencies,
    )


def build_demo_signals() -> list[MonitoringSignal]:
    """Generate sample monitoring signals for a local demonstration."""
    now = datetime.now(timezone.utc)

    return [
        MonitoringSignal(
            service="api",
            metric="cpu_usage_percent",
            value=96,
            observed_at=now,
            source="demo",
            message="CPU utilization is above threshold.",
        ),
        MonitoringSignal(
            service="api",
            metric="health_status",
            value="unhealthy",
            observed_at=now,
            source="demo",
            message="API health check failed.",
        ),
    ]


async def run_demo() -> int:
    """Run one local demonstration without requiring live infrastructure."""
    controller = load_controller()
    signals = build_demo_signals()

    result = await controller.process_signals(signals)

    import json

    print(json.dumps(result, indent=2, default=str))
    return 0


async def run_forever() -> None:
    """
    Minimal polling loop for normalized signals.

    Replace this demonstration source with a real monitoring adapter when
    integrating Prometheus, Alertmanager, or another monitoring system.
    """
    poll_seconds = 30

    LOGGER.info(
        "Recovery controller started in configured execution mode."
    )

    while True:
        # No synthetic production actions are performed by this loop.
        # A monitoring adapter should retrieve alerts and call process_signals.
        await asyncio.sleep(poll_seconds)


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )


def main() -> int:
    configure_logging()

    try:
        if "--demo" in sys.argv:
            return asyncio.run(run_demo())

        controller = load_controller()
        LOGGER.info(
            "Configuration loaded. Execution mode: %s",
            controller.executor.mode,
        )
        LOGGER.info(
            "Controller initialized. Use --demo to process sample signals."
        )

        # This entry point initializes the controller. A real monitoring
        # adapter must feed incoming signals into process_signals().
        return 0

    except (ConfigurationError, ValueError, TypeError) as exc:
        LOGGER.error("Startup failed: %s", exc)
        return 2
    except KeyboardInterrupt:
        LOGGER.info("Controller stopped.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())