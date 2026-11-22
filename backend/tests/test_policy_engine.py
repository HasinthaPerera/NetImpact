"""
Automated Pytest Test Suite for NetImpact Policy Engine and Security Guardrails.
Tests:
1. Baseline Permitted Access (Finance -> Finance DB)
2. Baseline Denied Access (HR -> Finance DB under current baseline)
3. Default-Deny Fallback (arbitrary unlisted traffic)
4. Critical Security Violation Detection (Proposed rule: HR -> Finance DB)
5. Safe Policy Addition (Legitimate new rule with no guardrail violations)
6. FastAPI Endpoint Integration Test via HTTPX
"""

import pytest
from app.main import app, health_check, get_topology, run_simulation
from app.models import PolicyRule, SimulationRequest
from app.policy_engine import (
    simulate_policy_change,
    load_current_policies,
    load_security_guardrails,
    evaluate_connection_against_rules
)


def test_baseline_finance_to_finance_db_permitted():
    """Scenario 1: Verified Finance workstations should be ALLOWED to reach Finance DB."""
    response = simulate_policy_change(
        source_segment="seg-finance",
        destination_resource="res-fin-db",
        port=5432,
        protocol="TCP",
        proposed_rule=None
    )
    
    assert response.current_evaluation.status == "ALLOWED"
    assert response.current_evaluation.matched_rule_id == "RULE-020"
    assert response.proposed_evaluation.status == "ALLOWED"
    assert response.change_type == "NO_CHANGE"
    assert response.risk_detected is False
    assert len(response.violations) == 0
    assert response.overall_verdict == "SAFE"


def test_baseline_hr_to_finance_db_denied():
    """Scenario 2: Under baseline policy, HR must be DENIED access to Finance DB."""
    response = simulate_policy_change(
        source_segment="seg-hr",
        destination_resource="res-fin-db",
        port=5432,
        protocol="TCP",
        proposed_rule=None
    )
    
    assert response.current_evaluation.status == "DENIED"
    assert response.current_evaluation.action == "DENY"
    # Matched rule should be the default deny rule (priority 999)
    assert response.current_evaluation.matched_rule_id == "RULE-999"
    assert response.proposed_evaluation.status == "DENIED"
    assert response.risk_detected is False
    assert response.overall_verdict == "BLOCKED"


def test_strict_default_deny_fallback():
    """Scenario 3: Any unknown or unmatched traffic must be DENIED by default-deny."""
    rules = load_current_policies()
    
    eval_result = evaluate_connection_against_rules(
        rules=rules,
        source_segment="seg-hr",
        destination_resource="res-it-jumpbox",
        port=9999,
        protocol="TCP"
    )
    
    assert eval_result.status == "DENIED"
    assert eval_result.action == "DENY"


def test_proposed_hr_to_finance_db_flags_critical_security_risk():
    """
    Scenario 4 (Core Milestone 1 Requirement):
    A proposed rule that introduces HR-to-Finance DB access MUST be flagged
    as a CRITICAL security violation before deployment.
    """
    proposed_rule = PolicyRule(
        id="RULE-PROPOSED-RISKY",
        name="Allow HR to Finance DB directly",
        source_segment="seg-hr",
        destination_resource="res-fin-db",
        port=5432,
        protocol="TCP",
        action="ALLOW",
        priority=15,  # Higher priority than RULE-999 default deny
        description="Dangerous change that breaches segregation of duties"
    )
    
    response = simulate_policy_change(
        source_segment="seg-hr",
        destination_resource="res-fin-db",
        port=5432,
        protocol="TCP",
        proposed_rule=proposed_rule
    )
    
    # 1. Before change: Access was DENIED
    assert response.current_evaluation.status == "DENIED"
    
    # 2. After change: Proposed rule ALLOWS access
    assert response.proposed_evaluation.status == "ALLOWED"
    assert response.proposed_evaluation.matched_rule_id == "RULE-PROPOSED-RISKY"
    assert response.change_type == "ACCESS_GRANTED"
    
    # 3. Security Guardrails: Critical violation MUST be detected!
    assert response.risk_detected is True
    assert len(response.violations) >= 1
    
    violation = response.violations[0]
    assert violation.guardrail_id == "SG-01"
    assert violation.severity == "CRITICAL"
    assert "HR to Finance Database Isolation" in violation.name
    
    # 4. Overall verdict must advise against deployment
    assert response.overall_verdict == "CRITICAL_RISK"
    assert "REJECT DEPLOYMENT" in response.recommendation


def test_proposed_safe_rule_no_risk():
    """
    Scenario 5: A proposed safe rule (e.g. IT accessing a diagnostic web port)
    should be permitted without triggering security violations.
    """
    safe_rule = PolicyRule(
        id="RULE-PROPOSED-SAFE",
        name="Allow IT to Finance Web Portal HTTPS",
        source_segment="seg-it",
        destination_resource="res-fin-web",
        port=443,
        protocol="TCP",
        action="ALLOW",
        priority=25,
        description="Safe management web traffic"
    )
    
    response = simulate_policy_change(
        source_segment="seg-it",
        destination_resource="res-fin-web",
        port=443,
        protocol="TCP",
        proposed_rule=safe_rule
    )
    
    assert response.proposed_evaluation.status == "ALLOWED"
    assert response.risk_detected is False
    assert len(response.violations) == 0


def test_fastapi_endpoints_integration():
    """Scenario 6: Verify FastAPI REST endpoints work end-to-end."""
    # Health check endpoint
    health_data = health_check()
    assert health_data["status"] == "ok"
    
    # Network topology endpoint
    topo_data = get_topology()
    assert len(topo_data["segments"]) == 3
    assert len(topo_data["resources"]) == 3
    
    # Simulate API endpoint
    sim_request = SimulationRequest(
        source_segment="seg-hr",
        destination_resource="res-fin-db",
        port=5432,
        protocol="TCP",
        proposed_rule=PolicyRule(
            id="RULE-TEST-001",
            name="Test Allow HR to Fin DB",
            source_segment="seg-hr",
            destination_resource="res-fin-db",
            port=5432,
            protocol="TCP",
            action="ALLOW",
            priority=5
        )
    )
    sim_response = run_simulation(sim_request)
    assert sim_response.risk_detected is True
    assert sim_response.overall_verdict == "CRITICAL_RISK"
    assert sim_response.proposed_evaluation.status == "ALLOWED"
    assert sim_response.current_evaluation.status == "DENIED"
