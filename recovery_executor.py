"""
recovery_executor.py

Risk-Aware Recovery Controller
Production Reliability + Controlled Automation

Executes approved recovery actions with:
- Dry-run mode by default
- Policy and allowlist validation
- Explicit approval checks for high-risk actions
- Execution timeouts and retry limits
- Pre- and post-recovery health verification
- Rollback handling when a rollback action is configured
- Structured execution results and audit logging

Safety note:
This module intentionally does not execute arbitrary shell commands.
Recovery operations must be explicitly implemented in the registered
action handlers.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Mapping, Sequence


logger = logging.getLogger("recovery_executor")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ExecutionMode(str, Enum):
    DRY_RUN = "dry_run"
    LIVE = "live"


class RecoveryStatus(str, Enum):
    PLANNED = "planned"
    BLOCKED = "blocked"
    AWAITING_APPROVAL = "awaiting_approval"
    DRY_RUN_SUCCESS = "dry_run_success"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLBACK_RUNNING = "rollback_running"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    VERIFICATION_FAILED = "verification_failed"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RecoveryAction:
    """
    A proposed recovery operation.

    action_type must match a registered handler. Parameters are passed to
    that handler and must be validated by the handler itself.
    """

    action_type: str
    service: str
    parameters: Mapping[str, Any] = field(default_factory=dict)

    risk_level: RiskLevel = RiskLevel.MEDIUM
    incident_id: str = ""
    description: str = ""

    requires_approval: bool = False
    approved: bool = False
    approval_reference: str | None = None

    rollback_action_type: str | None = None
    rollback_parameters: Mapping[str, Any] = field(default_factory=dict)

    timeout_seconds: float = 30.0
    max_attempts: int = 1

    # Optional expected service state after recovery.
    expected_health: str = "healthy"


@dataclass
class ExecutionResult:
    execution_id: str
    incident_id: str
    action_type: str
    service: str
    status: RecoveryStatus

    mode: ExecutionMode
    message: str

    started_at: str
    finished_at: str | None = None
    duration_seconds: float = 0.0

    attempts: int = 0
    health_before: bool | None = None
    health_after: bool | None = None

    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None

    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        result["mode"] = self.mode.value
        return result


# ---------------------------------------------------------------------------
# Handler contracts
# ---------------------------------------------------------------------------


ActionHandler = Callable[
    [RecoveryAction],
    Awaitable[Mapping[str, Any] | None],
]

HealthCheck = Callable[
    [str],
    Awaitable[bool],
]

AuditWriter = Callable[
    [Mapping[str, Any]],
    Awaitable[None],
]


# ---------------------------------------------------------------------------
# Recovery executor
# ---------------------------------------------------------------------------


class RecoveryExecutor:
    """
    Safely executes approved recovery actions.

    The executor defaults to DRY_RUN. Live execution is permitted only when:
      1. The executor is configured for LIVE mode.
      2. The action type is explicitly allowlisted.
      3. The action has passed policy validation.
      4. Required approvals are present.
      5. A corresponding handler is registered.

    Handlers should implement narrow, service-specific operations rather than
    accepting arbitrary shell commands or unrestricted scripts.
    """

    def __init__(
        self,
        *,
        mode: ExecutionMode = ExecutionMode.DRY_RUN,
        allowed_actions: Sequence[str] | None = None,
        approval_required_for: Sequence[RiskLevel] | None = None,
        default_timeout_seconds: float = 30.0,
        max_allowed_attempts: int = 3,
        retry_delay_seconds: float = 1.0,
        verify_health_before: bool = True,
        verify_health_after: bool = True,
        audit_writer: AuditWriter | None = None,
    ) -> None:
        self.mode = mode

        self.allowed_actions = set(allowed_actions or [])
        self.approval_required_for = set(
            approval_required_for
            or [RiskLevel.HIGH, RiskLevel.CRITICAL]
        )

        self.default_timeout_seconds = default_timeout_seconds
        self.max_allowed_attempts = max_allowed_attempts
        self.retry_delay_seconds = retry_delay_seconds

        self.verify_health_before = verify_health_before
        self.verify_health_after = verify_health_after

        self.audit_writer = audit_writer

        self._handlers: dict[str, ActionHandler] = {}
        self._health_checks: dict[str, HealthCheck] = {}

    # -----------------------------------------------------------------------
    # Registration
    # -----------------------------------------------------------------------

    def register_handler(
        self,
        action_type: str,
        handler: ActionHandler,
    ) -> None:
        """Register a trusted handler for a specific recovery action type."""

        normalized = self._validate_identifier(action_type, "action_type")

        if normalized in self._handlers:
            raise ValueError(
                f"A handler is already registered for '{normalized}'."
            )

        self._handlers[normalized] = handler

    def register_health_check(
        self,
        service: str,
        health_check: HealthCheck,
    ) -> None:
        """Register an asynchronous health check for a service."""

        normalized = self._validate_identifier(service, "service")

        self._health_checks[normalized] = health_check

    # -----------------------------------------------------------------------
    # Public execution API
    # -----------------------------------------------------------------------

    async def execute(
        self,
        action: RecoveryAction,
    ) -> ExecutionResult:
        """
        Validate and execute a recovery action.

        Exceptions from individual recovery handlers are captured and
        represented in the execution result. Invalid action definitions are
        rejected before execution.
        """

        self._validate_action(action)

        execution_id = str(uuid.uuid4())
        started_monotonic = time.monotonic()
        started_at = self._utc_now()

        result = ExecutionResult(
            execution_id=execution_id,
            incident_id=action.incident_id,
            action_type=action.action_type,
            service=action.service,
            status=RecoveryStatus.PLANNED,
            mode=self.mode,
            message="Recovery action received.",
            started_at=started_at,
        )

        await self._audit(
            "recovery_requested",
            result,
            {"description": action.description},
        )

        # Dry-run mode never invokes a recovery handler.
        if self.mode == ExecutionMode.DRY_RUN:
            result.status = RecoveryStatus.DRY_RUN_SUCCESS
            result.message = (
                "Dry run completed. No recovery operation was executed."
            )
            result.metadata["planned_parameters"] = dict(
                action.parameters
            )
            return await self._finish(result, started_monotonic)

        # Verify that the action is explicitly permitted.
        if action.action_type not in self.allowed_actions:
            result.status = RecoveryStatus.BLOCKED
            result.message = (
                "Action blocked because its type is not allowlisted."
            )
            return await self._finish(result, started_monotonic)

        # Require explicit approval for sensitive operations.
        approval_required = (
            action.requires_approval
            or action.risk_level in self.approval_required_for
        )

        if approval_required and not action.approved:
            result.status = RecoveryStatus.AWAITING_APPROVAL
            result.message = (
                "Recovery action requires approval before execution."
            )
            return await self._finish(result, started_monotonic)

        if approval_required and not action.approval_reference:
            result.status = RecoveryStatus.BLOCKED
            result.message = (
                "Approval reference is required for this action."
            )
            return await self._finish(result, started_monotonic)

        handler = self._handlers.get(action.action_type)

        if handler is None:
            result.status = RecoveryStatus.BLOCKED
            result.message = (
                f"No trusted handler is registered for "
                f"'{action.action_type}'."
            )
            return await self._finish(result, started_monotonic)

        # Pre-recovery health verification.
        if self.verify_health_before:
            health_before = await self._check_health(action.service)
            result.health_before = health_before

            if health_before is None:
                result.status = RecoveryStatus.BLOCKED
                result.message = (
                    "No health check is registered for the target service."
                )
                return await self._finish(result, started_monotonic)

            result.metadata["health_before_verified"] = True

        # Execute with bounded retries.
        result.status = RecoveryStatus.RUNNING
        result.message = "Recovery operation is running."

        await self._audit("recovery_started", result, {})

        operation_succeeded = await self._run_with_retries(
            action=action,
            handler=handler,
            result=result,
        )

        if not operation_succeeded:
            result.status = RecoveryStatus.FAILED
            result.message = "Recovery operation failed."
            await self._attempt_rollback(
                action=action,
                result=result,
            )
            return await self._finish(result, started_monotonic)

        # Post-recovery health verification.
        if self.verify_health_after:
            health_after = await self._check_health(action.service)
            result.health_after = health_after

            if health_after is not True:
                result.status = RecoveryStatus.VERIFICATION_FAILED
                result.message = (
                    "Recovery operation completed, but service health "
                    "could not be verified."
                )
                await self._attempt_rollback(
                    action=action,
                    result=result,
                )
                return await self._finish(result, started_monotonic)

        result.status = RecoveryStatus.SUCCEEDED
        result.message = (
            "Recovery operation completed and verification passed."
        )

        return await self._finish(result, started_monotonic)

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------

    def _validate_action(self, action: RecoveryAction) -> None:
        self._validate_identifier(action.action_type, "action_type")
        self._validate_identifier(action.service, "service")

        if action.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero.")

        if action.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1.")

        if action.max_attempts > self.max_allowed_attempts:
            raise ValueError(
                f"max_attempts cannot exceed "
                f"{self.max_allowed_attempts}."
            )

        if not isinstance(action.parameters, Mapping):
            raise ValueError("parameters must be a mapping.")

        if not isinstance(action.rollback_parameters, Mapping):
            raise ValueError("rollback_parameters must be a mapping.")

        if action.rollback_action_type:
            self._validate_identifier(
                action.rollback_action_type,
                "rollback_action_type",
            )

        if action.risk_level in self.approval_required_for:
            logger.info(
                "Action '%s' is classified as %s risk.",
                action.action_type,
                action.risk_level.value,
            )

    @staticmethod
    def _validate_identifier(value: str, field_name: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be a string.")

        normalized = value.strip()

        if not normalized:
            raise ValueError(f"{field_name} cannot be empty.")

        if len(normalized) > 128:
            raise ValueError(f"{field_name} is too long.")

        return normalized

    # -----------------------------------------------------------------------
    # Health verification
    # -----------------------------------------------------------------------

    async def _check_health(
        self,
        service: str,
    ) -> bool | None:
        health_check = self._health_checks.get(service)

        if health_check is None:
            return None

        try:
            async with asyncio.timeout(self.default_timeout_seconds):
                return bool(await health_check(service))
        except Exception:
            logger.exception(
                "Health check failed for service '%s'.",
                service,
            )
            return False

    # -----------------------------------------------------------------------
    # Action execution and retries
    # -----------------------------------------------------------------------

    async def _run_with_retries(
        self,
        *,
        action: RecoveryAction,
        handler: ActionHandler,
        result: ExecutionResult,
    ) -> bool:
        timeout_seconds = (
            action.timeout_seconds or self.default_timeout_seconds
        )

        for attempt in range(1, action.max_attempts + 1):
            result.attempts = attempt

            try:
                async with asyncio.timeout(timeout_seconds):
                    handler_result = await handler(action)

                if handler_result:
                    result.metadata["handler_result"] = dict(handler_result)

                await self._audit(
                    "recovery_attempt_succeeded",
                    result,
                    {"attempt": attempt},
                )
                return True

            except TimeoutError:
                result.error = (
                    f"Attempt {attempt} exceeded "
                    f"{timeout_seconds} seconds."
                )
                logger.warning(
                    "Recovery action '%s' timed out on attempt %s.",
                    action.action_type,
                    attempt,
                )

            except Exception as exc:
                result.error = f"{type(exc).__name__}: {exc}"
                logger.exception(
                    "Recovery action '%s' failed on attempt %s.",
                    action.action_type,
                    attempt,
                )

            await self._audit(
                "recovery_attempt_failed",
                result,
                {
                    "attempt": attempt,
                    "error": result.error,
                },
            )

            if attempt < action.max_attempts:
                await asyncio.sleep(self.retry_delay_seconds)

        return False

    # -----------------------------------------------------------------------
    # Rollback
    # -----------------------------------------------------------------------

    async def _attempt_rollback(
        self,
        *,
        action: RecoveryAction,
        result: ExecutionResult,
    ) -> None:
        """
        Run a configured rollback handler when available.

        Rollback is not guessed or generated dynamically. It must be explicitly
        configured and registered as a trusted action type.
        """

        rollback_type = action.rollback_action_type

        if not rollback_type:
            result.metadata["rollback_message"] = (
                "No rollback action was configured."
            )
            return

        rollback_handler = self._handlers.get(rollback_type)

        if rollback_handler is None:
            result.metadata["rollback_message"] = (
                f"No handler is registered for rollback action "
                f"'{rollback_type}'."
            )
            return

        if rollback_type not in self.allowed_actions:
            result.metadata["rollback_message"] = (
                "Rollback blocked because its action type is not allowlisted."
            )
            return

        result.rollback_attempted = True
        result.status = RecoveryStatus.ROLLBACK_RUNNING

        rollback_action = RecoveryAction(
            action_type=rollback_type,
            service=action.service,
            parameters=action.rollback_parameters,
            risk_level=action.risk_level,
            incident_id=action.incident_id,
            description=f"Rollback for {action.action_type}",
            requires_approval=action.requires_approval,
            approved=action.approved,
            approval_reference=action.approval_reference,
            timeout_seconds=action.timeout_seconds,
            max_attempts=1,
            expected_health=action.expected_health,
        )

        try:
            async with asyncio.timeout(action.timeout_seconds):
                rollback_result = await rollback_handler(rollback_action)

            result.rollback_succeeded = True
            result.status = RecoveryStatus.ROLLED_BACK
            result.metadata["rollback_result"] = (
                dict(rollback_result) if rollback_result else {}
            )

            # Verify service health after rollback where possible.
            if self.verify_health_after:
                rollback_health = await self._check_health(action.service)
                result.metadata["health_after_rollback"] = rollback_health

                if rollback_health is not True:
                    result.status = RecoveryStatus.ROLLBACK_FAILED
                    result.rollback_succeeded = False
                    result.metadata["rollback_message"] = (
                        "Rollback handler completed, but service health "
                        "was not verified."
                    )

        except Exception as exc:
            result.rollback_succeeded = False
            result.status = RecoveryStatus.ROLLBACK_FAILED
            result.metadata["rollback_error"] = (
                f"{type(exc).__name__}: {exc}"
            )

            logger.exception(
                "Rollback '%s' failed for service '%s'.",
                rollback_type,
                action.service,
            )

        await self._audit(
            "rollback_finished",
            result,
            {
                "rollback_action_type": rollback_type,
                "rollback_succeeded": result.rollback_succeeded,
            },
        )

    # -----------------------------------------------------------------------
    # Audit and result helpers
    # -----------------------------------------------------------------------

    async def _audit(
        self,
        event_type: str,
        result: ExecutionResult,
        details: Mapping[str, Any],
    ) -> None:
        record = {
            "event_type": event_type,
            "timestamp": self._utc_now(),
            "execution_id": result.execution_id,
            "incident_id": result.incident_id,
            "action_type": result.action_type,
            "service": result.service,
            "status": result.status.value,
            "mode": result.mode.value,
            "details": dict(details),
        }

        logger.info("RECOVERY_AUDIT %s", record)

        if self.audit_writer is not None:
            try:
                await self.audit_writer(record)
            except Exception:
                # Audit failures are logged. Production systems should decide
                # whether their audit policy requires fail-closed behavior.
                logger.exception("Failed to write recovery audit record.")

    async def _finish(
        self,
        result: ExecutionResult,
        started_monotonic: float,
    ) -> ExecutionResult:
        result.finished_at = self._utc_now()
        result.duration_seconds = round(
            time.monotonic() - started_monotonic,
            4,
        )

        await self._audit(
            "recovery_finished",
            result,
            {
                "duration_seconds": result.duration_seconds,
                "attempts": result.attempts,
                "rollback_attempted": result.rollback_attempted,
                "rollback_succeeded": result.rollback_succeeded,
            },
        )

        return result

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Example safe handler registration
# ---------------------------------------------------------------------------


async def example_restart_handler(
    action: RecoveryAction,
) -> Mapping[str, Any]:
    """
    Demonstration handler only.

    Replace this with a narrowly scoped integration for your environment,
    such as a Kubernetes client or an authorized service-management API.
    Do not implement arbitrary command execution here.
    """

    if action.service != "demo-service":
        raise ValueError("Example handler only supports demo-service.")

    # No real restart is performed.
    logger.info(
        "Example restart handler invoked for service '%s'.",
        action.service,
    )

    return {
        "operation": "example_restart",
        "service": action.service,
        "executed": False,
        "message": "Replace this demonstration handler with a real integration.",
    }


async def example_health_check(service: str) -> bool:
    """
    Demonstration health check.

    Replace this with an actual health endpoint or service-specific probe.
    """

    return service == "demo-service"


def build_example_executor() -> RecoveryExecutor:
    """
    Build a safe example executor.

    Dry-run is enabled by default. Live execution requires explicitly
    selecting LIVE mode and configuring the action allowlist.
    """

    executor = RecoveryExecutor(
        mode=ExecutionMode.DRY_RUN,
        allowed_actions=["restart_service"],
        approval_required_for=[
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ],
        verify_health_before=True,
        verify_health_after=True,
    )

    executor.register_handler(
        "restart_service",
        example_restart_handler,
    )

    executor.register_health_check(
        "demo-service",
        example_health_check,
    )

    return executor


# ---------------------------------------------------------------------------
# Standalone demonstration
# ---------------------------------------------------------------------------


async def _demo() -> None:
    executor = build_example_executor()

    action = RecoveryAction(
        action_type="restart_service",
        service="demo-service",
        parameters={"reason": "simulated_health_check_failure"},
        risk_level=RiskLevel.LOW,
        incident_id="INC-DEMO-001",
        description="Demonstration recovery action",
        expected_health="healthy",
    )

    result = await executor.execute(action)

    print(result.to_dict())


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(_demo())