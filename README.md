# 🚨 Risk-Aware Recovery Controller — Production Reliability + Controlled Automation

<div align="center">

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyYAML](https://img.shields.io/badge/PyYAML-Configuration-CB171E?style=for-the-badge&logo=yaml&logoColor=white)
![Reliability](https://img.shields.io/badge/Production-Reliability-2E8B57?style=for-the-badge)
![Automation](https://img.shields.io/badge/Recovery-Controlled_Automation-6C5CE7?style=for-the-badge)
![Safety](https://img.shields.io/badge/Safety-Risk_Aware-orange?style=for-the-badge)
![Execution](https://img.shields.io/badge/Default_Mode-Dry_Run-008CBA?style=for-the-badge)

</div>

---

# 👨‍💻 Developed By

### Pradeep

---

# 📂 Repository Name

### `risk-aware-recovery-controller`

---

# 🚀 About This Project

The Risk-Aware Recovery Controller is a Python-based reliability engineering project designed to detect production service incidents, assess operational risk, generate recovery plans, and execute approved recovery actions through a controlled automation workflow.

Production environments depend on multiple interconnected services. When a service becomes unhealthy, experiences high resource utilization, or develops performance issues, recovery actions must be selected carefully. An inappropriate automated action can increase downtime, affect dependent services, or introduce additional operational risk.

This project combines incident detection, risk assessment, dependency-aware recovery planning, and controlled execution into a single workflow. YAML-based configuration defines detection rules, service dependencies, recovery policies, and permitted actions.

The controller defaults to dry-run execution, supports approval requirements for high-risk operations, and maintains an audit trail of execution attempts. Live recovery is subject to explicit configuration and environment-variable safeguards.

The project provides a foundation for experimenting with safer, policy-driven production incident recovery.

---

# ❗ Problem Statement

Production reliability teams face several challenges when responding to service incidents:

- Identifying unhealthy services from monitoring signals.
- Correlating multiple symptoms into a meaningful incident.
- Understanding the potential impact of an incident on dependent services.
- Selecting recovery actions that comply with operational policies.
- Preventing risky or unauthorized automated changes.
- Requiring human approval for sensitive recovery operations.
- Recording recovery decisions and execution attempts for auditing.
- Avoiding unnecessary or repeated recovery attempts.

The project addresses these challenges by introducing a structured recovery workflow that combines incident detection, risk evaluation, recovery planning, policy validation, and controlled action execution.

---

# 🎯 System Objectives

- Detect incidents from service monitoring signals.
- Correlate related signals within a configurable time window.
- Identify affected services and possible causes.
- Assess incident risk using severity, service criticality, customer impact, and other factors.
- Generate recovery plans based on configured policies.
- Consider service dependencies when ordering recovery actions.
- Validate actions against configured service and action allowlists.
- Require approval for high-risk and critical operations.
- Default to dry-run execution to reduce the risk of unintended changes.
- Record execution activity in an audit log.
- Support a controlled path toward live recovery when explicitly enabled.

---

# ✨ Key Features

## 🚨 Incident Detection and Correlation

- Evaluate monitoring signals against configurable detection rules.
- Detect high CPU utilization, high memory utilization, elevated error rates, high latency, and unhealthy service status.
- Correlate related signals within a configurable time window.
- Identify the primary affected service and other affected services.
- Map detected symptoms to configured suspected causes.
- Generate structured incident information for downstream processing.

## 🧠 Risk Assessment Engine

- Calculate a risk score using incident characteristics.
- Consider service criticality, incident severity, affected service count, customer impact, and potential data loss.
- Classify risk into LOW, MEDIUM, HIGH, or CRITICAL levels.
- Determine whether human approval is required.
- Recommend a suitable execution mode based on assessed risk.
- Prevent recovery actions when configured risk restrictions are violated.

> Risk scores and classifications are decision-support signals. They do not guarantee that a recovery action is safe or that an incident has been correctly diagnosed.

## 🗺️ Dependency-Aware Recovery Planning

- Generate recovery plans from incident assessments.
- Use YAML-based recovery policies to select permitted actions.
- Consider service dependencies when determining recovery order.
- Reject unknown, disabled, or disallowed actions when policy validation requires it.
- Apply configured risk levels, action priorities, timeouts, and retry limits.
- Validate recovery plans before execution.

## ⚙️ Controlled Recovery Execution

- Support dry-run and live execution modes.
- Default to dry-run execution.
- Restrict execution to configured action types.
- Apply bounded timeouts and retry limits.
- Support approval requirements for high-risk actions.
- Provide an execution interface for registered recovery handlers.
- Support rollback action configuration where an appropriate handler is available.

Live execution requires explicit configuration and the `ALLOW_LIVE_RECOVERY=true` environment setting. Actual recovery also requires suitable action handlers, health checks, permissions, and environment-specific integration.

## 🛡️ Safety and Approval Controls

- Keep automated recovery behind explicit policy checks.
- Require approval for configured high-risk and critical operations.
- Reject actions that are not permitted by the recovery policy.
- Avoid enabling live execution through configuration alone.
- Maintain execution records for operational review.
- Provide a dry-run workflow for testing recovery decisions without performing live changes.

## 📜 Audit Logging

- Record recovery execution attempts.
- Capture action details and execution outcomes where supported by the executor.
- Use a configurable audit log path.
- Support investigation of recovery decisions and failures.
- Keep audit information available for troubleshooting and review.

## 📄 Configuration-Driven Policies

- Define detection thresholds in `config.yaml`.
- Configure recovery action behavior in `recovery_policies.yaml`.
- Model service relationships in `service_dependencies.yaml`.
- Configure execution mode, timeouts, retry limits, and approval requirements.
- Keep environment-specific settings separate from Python implementation code.

---

# 🏗️ System Architecture

The project is organized into five primary processing stages: incident detection, risk assessment, recovery planning, policy validation, and controlled execution.

## Core Components

- **Incident Detector:** Evaluates monitoring signals, identifies symptoms, and groups related signals into incidents.
- **Risk Assessor:** Calculates operational risk and recommends appropriate execution controls.
- **Recovery Planner:** Builds recovery plans using configured policies and service dependencies.
- **Recovery Executor:** Runs permitted recovery actions through registered handlers, subject to execution safeguards.
- **YAML Configuration:** Defines incident rules, recovery policies, service dependencies, and runtime settings.
- **Audit Logging:** Records recovery execution activity for later review.
- **Main Controller:** Coordinates the end-to-end workflow.

## High-Level Flow

```text
Monitoring Signals
        |
        v
Incident Detector
        |
        v
Incident Correlation
        |
        v
Risk Assessment Engine
        |
        v
Recovery Planner
        |
        v
Plan and Policy Validation
        |
        v
Risk and Approval Checks
        |
        v
Recovery Executor
        |
        +------> Dry-Run Execution
        |
        +------> Approved Live Execution
        |
        v
Execution Result and Audit Log
```

Live execution is conditional. A recovery plan may be generated successfully without being executed if risk, approval, configuration, or execution prerequisites are not satisfied.

---

# ⚙️ Technologies Used

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyYAML](https://img.shields.io/badge/PyYAML-CB171E?style=for-the-badge&logo=yaml&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-E92063?style=for-the-badge&logo=pydantic&logoColor=white)
![HTTPX](https://img.shields.io/badge/HTTPX-HTTP_Client-005571?style=for-the-badge)
![Git](https://img.shields.io/badge/Git-Version_Control-F05032?style=for-the-badge&logo=git&logoColor=white)

</div>

## Technologies Included

- Python 3.12+
- PyYAML for configuration and policy files
- Pydantic for data validation capabilities where integrated
- HTTPX for HTTP integration capabilities where integrated
- python-dotenv for local environment configuration
- YAML for detection rules, recovery policies, and service dependencies
- Python dataclasses and enums for structured incident and recovery models
- Environment variables for execution safeguards
- JSON Lines-compatible audit logging

Some listed packages support future integration work and may not be used by every module in the current implementation.

---

# 📁 File Structure

```text
risk-aware-recovery-controller/
│
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── config.yaml
├── recovery_policies.yaml
├── service_dependencies.yaml
├── main.py
├── incident_detector.py
├── risk_assessor.py
├── recovery_planner.py
└── recovery_executor.py
```

## File Responsibilities

| File | Responsibility |
|---|---|
| `README.md` | Project overview, setup, architecture, and usage |
| `requirements.txt` | Python package dependencies |
| `.env.example` | Example environment variables |
| `.gitignore` | Excludes local secrets, virtual environments, and generated files |
| `config.yaml` | Runtime settings and incident detection rules |
| `recovery_policies.yaml` | Risk thresholds, action definitions, approval rules, and recovery selection policies |
| `service_dependencies.yaml` | Service dependency relationships and recovery ordering metadata |
| `main.py` | Coordinates the recovery controller workflow |
| `incident_detector.py` | Detects and correlates incidents |
| `risk_assessor.py` | Calculates incident and action risk |
| `recovery_planner.py` | Generates and validates recovery plans |
| `recovery_executor.py` | Executes recovery actions with safety controls and audit logging |

---

# ⚙️ Installation and Setup

## 1️⃣ Prerequisites

Install the following before starting:

- Python 3.12 or later
- pip
- Git, if cloning the repository
- A terminal or command prompt

## 2️⃣ Clone the Repository

If the project is hosted in a Git repository:

```bash
git clone <repository-url>
cd risk-aware-recovery-controller
```

If the files are already on your computer, open a terminal in the project root instead.

## 3️⃣ Create a Virtual Environment

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 4️⃣ Install Dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 5️⃣ Configure Environment Variables

Create a local `.env` file from the example.

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

### Linux / macOS

```bash
cp .env.example .env
```

Review the environment settings before running the application.

For initial testing, keep:

```dotenv
RECOVERY_EXECUTION_MODE=dry_run
ALLOW_LIVE_RECOVERY=false
```

Do not commit `.env` or real credentials to version control. Environment variables must be loaded by the application or your shell; creating a `.env` file alone does not automatically guarantee that Python reads it.

## 6️⃣ Validate the YAML Configuration

Check that all three configuration files exist in the project root:

```text
config.yaml
recovery_policies.yaml
service_dependencies.yaml
```

You can perform a basic YAML parsing check with:

```bash
python -c "import yaml; from pathlib import Path; files=['config.yaml','recovery_policies.yaml','service_dependencies.yaml']; [yaml.safe_load(Path(f).read_text(encoding='utf-8')) for f in files]; print('YAML files parsed successfully')"
```

This checks YAML syntax. It does not guarantee that every configuration value matches the expectations of the application code.

---

# ▶️ Running the Project

## 1️⃣ Run the Demonstration Workflow

From the project root, with the virtual environment activated, run:

```bash
python main.py --demo
```

The demo is intended to exercise the incident detection and recovery-planning workflow using sample signals.

Keep the controller in dry-run mode during initial testing.

## 2️⃣ Review the Output

Review the application output for:

- Detected incident details
- Identified affected services and symptoms
- Risk level and risk score
- Generated recovery plan
- Policy validation results
- Approval requirements
- Execution mode and recovery outcome

The exact output depends on the implementation, configuration, sample signals, and available recovery handlers.

## 3️⃣ Review the Audit Log

The default configuration specifies the following audit log path:

```text
recovery_audit.jsonl
```

After execution attempts, inspect this file if it has been created. It should be treated as an operational record, not as a substitute for centralized, tamper-resistant audit storage.

---

# 🔄 System Workflow

### 1️⃣ Monitoring Signal Collection

The controller receives monitoring signals containing service names, metric values, timestamps, and related context.

### 2️⃣ Incident Detection

The incident detector compares signals against configured thresholds and identifies matching symptoms.

### 3️⃣ Incident Correlation

Related signals are grouped within the configured correlation window to help identify affected services and possible causes.

### 4️⃣ Risk Assessment

The risk assessor evaluates incident severity, service criticality, customer impact, potential data loss, and other configured factors.

### 5️⃣ Recovery Plan Generation

The planner evaluates the incident against recovery policies and service dependency information to create a proposed recovery plan.

### 6️⃣ Policy Validation

The plan is checked against configured service restrictions, action allowlists, enabled actions, and risk policies.

### 7️⃣ Approval and Execution Controls

The controller determines whether the action can proceed, requires approval, or should remain in dry-run mode.

### 8️⃣ Recovery Execution

When permitted, the executor invokes a registered recovery handler with configured timeout and retry limits. Without a suitable handler or the required health-check configuration, live recovery cannot be assumed to work.

### 9️⃣ Audit and Review

The controller records execution activity where supported, allowing engineers to review outcomes and improve recovery policies.

---

# 🧪 Validation and Testing

Start with configuration validation and dry-run scenarios before connecting any production systems.

## Recommended Validation Checklist

- Confirm that all required Python files are present.
- Verify that dependencies install successfully.
- Parse all YAML configuration files.
- Run the demonstration workflow.
- Test detection rules with healthy and unhealthy signals.
- Verify incident severity and risk classification.
- Confirm that recovery plans respect service dependencies.
- Confirm that unknown or disabled actions are rejected when required by policy.
- Verify that high-risk operations are subject to approval checks.
- Confirm that dry-run execution does not invoke live infrastructure changes.
- Review generated audit records.
- Test recovery handlers and rollback behavior in an isolated environment before enabling live execution.

The repository's 12-file structure does not include a dedicated `tests/` directory. Automated unit and integration tests should be added before treating the project as validated for production use.

---

# 🛡️ Configuration and Security Notes

- Keep `RECOVERY_EXECUTION_MODE=dry_run` during development and initial validation.
- Keep `ALLOW_LIVE_RECOVERY=false` unless live execution has been explicitly approved.
- Do not place credentials, access tokens, or production secrets in source code.
- Use a secrets manager or approved environment-specific secret storage for sensitive values.
- Apply least-privilege permissions to recovery handlers and service accounts.
- Restrict the actions available to the executor through explicit allowlists.
- Require human approval for high-risk and critical recovery operations.
- Use bounded timeouts and retry limits to prevent uncontrolled execution.
- Protect audit logs from unauthorized modification or deletion.
- Test recovery actions in a non-production environment before using them in production.
- Confirm service health after recovery actions and define appropriate rollback procedures.

**Important:** Enabling live execution is not sufficient by itself to make recovery safe. Actual production integration requires validated handlers, health checks, access controls, approval workflows, and environment-specific testing.

---

# ⚠️ Current Scope and Limitations

- Incident detection depends on the monitoring signals supplied to the controller.
- The project does not automatically collect production telemetry unless a monitoring integration is implemented and configured.
- Cause mappings and recovery selection rules are policy-based; they do not guarantee identification of the true root cause.
- Service dependency definitions must be maintained and validated.
- Recovery execution depends on registered action handlers and suitable health checks.
- Human approval must be connected to a trusted approval process if approvals are to be enforced operationally.
- Audit logging requires appropriate storage permissions, retention, and monitoring.
- The current project structure does not include a dedicated API server, web dashboard, or production monitoring collector.
- The current project structure does not include a dedicated automated test suite.
- Production readiness requires additional integration, security review, testing, observability, and operational controls.

---

# 🚀 Future Improvements

- Integrate Prometheus or another monitoring platform for automated signal collection.
- Add a durable incident and recovery history store.
- Implement authenticated human approval workflows.
- Add real service-management and orchestration integrations.
- Implement service-specific health checks and recovery handlers.
- Improve dependency mapping and recovery-order validation.
- Add automated unit, integration, and failure-injection tests.
- Add structured logging and centralized audit storage.
- Add recovery metrics, dashboards, and alerting.
- Implement idempotency and duplicate-incident suppression.
- Add rate limits and safeguards against repeated recovery loops.
- Introduce controlled canary execution and staged rollout policies.
- Evaluate recovery effectiveness using historical incident scenarios.

---

# 🌍 Potential Use Cases

### 🚨 Production Incident Response

Detect unhealthy services and generate policy-based recovery plans.

### 🛡️ Risk-Aware Automation

Apply risk checks and approval requirements before attempting operational changes.

### 🔗 Dependency-Aware Recovery

Plan recovery actions with service relationships and ordering constraints in mind.

### 🧰 Site Reliability Engineering

Explore automation patterns for incident handling, operational safety, and reliability improvement.

### 🧪 Disaster Recovery Exercises

Evaluate recovery policies and proposed actions in dry-run scenarios before conducting controlled recovery tests.

---

# 🏁 Conclusion

The Risk-Aware Recovery Controller combines incident detection, risk assessment, dependency-aware recovery planning, and controlled execution into a structured Python-based reliability engineering workflow.

Its configuration-driven policies, dry-run default, approval controls, bounded execution settings, and audit logging provide a foundation for exploring safer operational automation.

The project is an extensible starting point rather than a complete production recovery platform. Before live deployment, it requires validated infrastructure integrations, reliable health checks, enforceable approval workflows, automated tests, secure audit storage, and a thorough review of operational risks.
