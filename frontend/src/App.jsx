import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Network,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Database,
  Lock,
  Play,
  FileText,
  Server,
  Layers,
  HelpCircle
} from 'lucide-react';

const FALLBACK_SEGMENTS = [
  {
    id: "seg-hr",
    name: "Human Resources Segment",
    cidr: "10.10.1.0/24",
    security_zone: "Internal-General",
    description: "Standard corporate workstations for HR staff. Should only access general intranet."
  },
  {
    id: "seg-finance",
    name: "Finance Segment",
    cidr: "10.10.2.0/24",
    security_zone: "Finance-Restricted",
    description: "Dedicated subnet for finance team workstations and financial processing."
  },
  {
    id: "seg-it",
    name: "IT Administration Segment",
    cidr: "10.10.3.0/24",
    security_zone: "Management-Restricted",
    description: "Privileged administration network for IT operations, jump hosts, and network engineering."
  }
];

const FALLBACK_RESOURCES = [
  {
    id: "res-fin-db",
    name: "Finance Core Database",
    ip: "10.10.2.50",
    port: 5432,
    protocol: "TCP",
    segment_id: "seg-finance",
    is_critical: true,
    description: "High-security PostgreSQL database storing company ledger, bank accounts, and payroll records."
  },
  {
    id: "res-fin-web",
    name: "Finance Internal Portal",
    ip: "10.10.2.20",
    port: 443,
    protocol: "TCP",
    segment_id: "seg-finance",
    is_critical: false,
    description: "Internal web portal used for corporate expense reports and travel reimbursements."
  },
  {
    id: "res-it-jumpbox",
    name: "IT Management Jumpbox",
    ip: "10.10.3.10",
    port: 22,
    protocol: "TCP",
    segment_id: "seg-it",
    is_critical: false,
    description: "Bastion server used by IT administrators for secure SSH access into production infrastructure."
  }
];

const FALLBACK_POLICIES = [
  {
    id: "RULE-010",
    name: "Allow IT SSH to Management Jumpbox",
    source_segment: "seg-it",
    destination_resource: "res-it-jumpbox",
    port: 22,
    protocol: "TCP",
    action: "ALLOW",
    priority: 10,
    description: "Permits IT administrators secure SSH access to the management bastion."
  },
  {
    id: "RULE-020",
    name: "Allow Finance to Finance Core Database",
    source_segment: "seg-finance",
    destination_resource: "res-fin-db",
    port: 5432,
    protocol: "TCP",
    action: "ALLOW",
    priority: 20,
    description: "Authorized database queries from verified Finance staff machines."
  },
  {
    id: "RULE-030",
    name: "Allow Corporate Users to Finance Expense Portal",
    source_segment: "*",
    destination_resource: "res-fin-web",
    port: 443,
    protocol: "TCP",
    action: "ALLOW",
    priority: 30,
    description: "Enables all corporate users (HR, Finance, IT) to submit expense reports over HTTPS."
  },
  {
    id: "RULE-999",
    name: "Default Deny All",
    source_segment: "*",
    destination_resource: "*",
    port: null,
    protocol: "ANY",
    action: "DENY",
    priority: 999,
    description: "Implicit default-deny baseline for zero-trust security."
  }
];

const FALLBACK_GUARDRAILS = [
  {
    id: "SG-01",
    name: "HR to Finance Database Isolation",
    forbidden_source: "seg-hr",
    forbidden_destination: "res-fin-db",
    severity: "CRITICAL",
    description: "The HR subnet must NEVER have direct access to the Finance Core Database.",
    rationale: "Violates Segregation of Duties (SoD) under SOC2, ISO 27001, and PCI-DSS standards."
  },
  {
    id: "SG-02",
    name: "Block Untrusted Direct Access to Management Jumpbox",
    forbidden_source: "seg-hr",
    forbidden_destination: "res-it-jumpbox",
    severity: "HIGH",
    description: "Non-IT departments are barred from administrative bastion jumpboxes.",
    rationale: "Prevents lateral movement and privilege escalation by non-administrative users."
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('simulator');
  const [backendOnline, setBackendOnline] = useState(false);
  const [loading, setLoading] = useState(false);

  // Data states
  const [segments, setSegments] = useState(FALLBACK_SEGMENTS);
  const [resources, setResources] = useState(FALLBACK_RESOURCES);
  const [policies, setPolicies] = useState(FALLBACK_POLICIES);
  const [guardrails, setGuardrails] = useState(FALLBACK_GUARDRAILS);

  // Form State
  const [sourceSegment, setSourceSegment] = useState('seg-hr');
  const [destinationResource, setDestinationResource] = useState('res-fin-db');
  const [port, setPort] = useState(5432);
  const [protocol, setProtocol] = useState('TCP');

  // Proposed Rule State
  const [hasProposedRule, setHasProposedRule] = useState(true);
  const [proposedRuleName, setProposedRuleName] = useState('Allow HR to Finance Database Direct');
  const [proposedRuleAction, setProposedRuleAction] = useState('ALLOW');
  const [proposedRulePriority, setProposedRulePriority] = useState(15);

  // Simulation Results
  const [simulationResult, setSimulationResult] = useState(null);

  // Initial Data Fetch
  useEffect(() => {
    checkBackendHealth();
  }, []);

  const checkBackendHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        setBackendOnline(true);
        fetchTopology();
        fetchPolicies();
        fetchGuardrails();
      } else {
        setBackendOnline(false);
      }
    } catch {
      setBackendOnline(false);
    }
  };

  const fetchTopology = async () => {
    try {
      const res = await fetch('/api/network-topology');
      if (res.ok) {
        const data = await res.json();
        setSegments(data.segments);
        setResources(data.resources);
      }
    } catch {
      // Keep fallbacks
    }
  };

  const fetchPolicies = async () => {
    try {
      const res = await fetch('/api/policies/current');
      if (res.ok) {
        const data = await res.json();
        setPolicies(data);
      }
    } catch {
      // Keep fallbacks
    }
  };

  const fetchGuardrails = async () => {
    try {
      const res = await fetch('/api/security-guardrails');
      if (res.ok) {
        const data = await res.json();
        setGuardrails(data);
      }
    } catch {
      // Keep fallbacks
    }
  };

  // Preset Handlers
  const loadScenario = (type) => {
    if (type === 'risky-hr') {
      setSourceSegment('seg-hr');
      setDestinationResource('res-fin-db');
      setPort(5432);
      setProtocol('TCP');
      setHasProposedRule(true);
      setProposedRuleName('Allow HR to Finance DB directly');
      setProposedRuleAction('ALLOW');
      setProposedRulePriority(15);
    } else if (type === 'safe-finance') {
      setSourceSegment('seg-finance');
      setDestinationResource('res-fin-db');
      setPort(5432);
      setProtocol('TCP');
      setHasProposedRule(false);
    } else if (type === 'denied-jumpbox') {
      setSourceSegment('seg-hr');
      setDestinationResource('res-it-jumpbox');
      setPort(22);
      setProtocol('TCP');
      setHasProposedRule(false);
    } else if (type === 'safe-portal') {
      setSourceSegment('seg-hr');
      setDestinationResource('res-fin-web');
      setPort(443);
      setProtocol('TCP');
      setHasProposedRule(false);
    }
  };

  // Run Simulation
  const handleSimulate = async () => {
    setLoading(true);

    const payload = {
      source_segment: sourceSegment,
      destination_resource: destinationResource,
      port: parseInt(port, 10),
      protocol: protocol.toUpperCase(),
      proposed_rule: hasProposedRule ? {
        id: "RULE-PROPOSED-" + Math.floor(Math.random() * 1000),
        name: proposedRuleName,
        source_segment: sourceSegment,
        destination_resource: destinationResource,
        port: parseInt(port, 10),
        protocol: protocol.toUpperCase(),
        action: proposedRuleAction,
        priority: parseInt(proposedRulePriority, 10),
        description: "User-defined proposed rule simulated via NetImpact"
      } : null
    };

    try {
      const response = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        const data = await response.json();
        setSimulationResult(data);
        setBackendOnline(true);
        setLoading(false);
        return;
      }
    } catch {
      // Backend offline: run client-side simulation fallback
    }

    // Client-side fallback simulation logic for offline testing
    setTimeout(() => {
      const sourceObj = segments.find(s => s.id === sourceSegment);
      const destObj = resources.find(r => r.id === destinationResource);

      // Baseline current evaluation
      let currentStatus = "DENIED";
      let currentRule = "Default Deny All (Priority 999)";
      let currentRuleId = "RULE-999";

      if (sourceSegment === 'seg-finance' && destinationResource === 'res-fin-db' && port === 5432) {
        currentStatus = "ALLOWED";
        currentRule = "Allow Finance to Finance Core Database (Priority 20)";
        currentRuleId = "RULE-020";
      } else if (destinationResource === 'res-fin-web' && port === 443) {
        currentStatus = "ALLOWED";
        currentRule = "Allow Corporate Users to Finance Expense Portal (Priority 30)";
        currentRuleId = "RULE-030";
      } else if (sourceSegment === 'seg-it' && destinationResource === 'res-it-jumpbox' && port === 22) {
        currentStatus = "ALLOWED";
        currentRule = "Allow IT SSH to Management Jumpbox (Priority 10)";
        currentRuleId = "RULE-010";
      }

      // Proposed evaluation
      let proposedStatus = currentStatus;
      let proposedRuleTitle = currentRule;
      let proposedId = currentRuleId;
      let proposedPrio = 999;

      if (hasProposedRule) {
        proposedStatus = proposedRuleAction === "ALLOW" ? "ALLOWED" : "DENIED";
        proposedRuleTitle = `${proposedRuleName} (Priority ${proposedRulePriority})`;
        proposedId = "RULE-PROPOSED";
        proposedPrio = proposedRulePriority;
      }

      // Guardrail check
      const violations = [];
      let riskDetected = false;

      if (proposedStatus === "ALLOWED") {
        if (sourceSegment === 'seg-hr' && destinationResource === 'res-fin-db') {
          riskDetected = true;
          violations.push({
            guardrail_id: "SG-01",
            name: "HR to Finance Database Isolation",
            severity: "CRITICAL",
            description: "The HR subnet must NEVER have direct access to the Finance Core Database.",
            rationale: "Violates Segregation of Duties (SoD) under SOC2 and PCI-DSS compliance frameworks."
          });
        }
      }

      const result = {
        source_segment: sourceSegment,
        source_segment_name: sourceObj ? sourceObj.name : sourceSegment,
        destination_resource: destinationResource,
        destination_resource_name: destObj ? destObj.name : destinationResource,
        destination_ip: destObj ? destObj.ip : '10.10.x.x',
        port: port,
        protocol: protocol,
        is_critical_target: destObj ? destObj.is_critical : false,
        current_evaluation: {
          status: currentStatus,
          matched_rule_id: currentRuleId,
          matched_rule_name: currentRule,
          matched_rule_priority: 20,
          action: currentStatus === "ALLOWED" ? "ALLOW" : "DENY",
          explanation: `Evaluated under baseline rules: Action is ${currentStatus}.`
        },
        proposed_evaluation: {
          status: proposedStatus,
          matched_rule_id: proposedId,
          matched_rule_name: proposedRuleTitle,
          matched_rule_priority: proposedPrio,
          action: proposedStatus === "ALLOWED" ? "ALLOW" : "DENY",
          explanation: `Evaluated with proposed change: Action is ${proposedStatus}.`
        },
        change_type: currentStatus === proposedStatus ? "NO_CHANGE" : (proposedStatus === "ALLOWED" ? "ACCESS_GRANTED" : "ACCESS_REVOKED"),
        risk_detected: riskDetected,
        violations: violations,
        overall_verdict: riskDetected ? "CRITICAL_RISK" : (proposedStatus === "ALLOWED" ? "POLICY_CHANGE_OK" : "BLOCKED"),
        recommendation: riskDetected 
          ? "REJECT DEPLOYMENT: Proposed rule violates critical security guardrail SG-01 (HR to Finance Database Isolation)."
          : "SAFE TO REVIEW: Proposed configuration complies with active security policies."
      };

      setSimulationResult(result);
      setLoading(false);
    }, 200);
  };

  return (
    <div className="app-layout">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <div className="logo-icon">
            <Shield size={22} />
          </div>
          <div className="logo-text">
            <h1>NetImpact</h1>
            <p>Policy Risk Platform</p>
          </div>
        </div>

        <nav className="sidebar-nav">
          <button
            className={`nav-item ${activeTab === 'simulator' ? 'active' : ''}`}
            onClick={() => setActiveTab('simulator')}
          >
            <Play size={18} />
            <span>Policy Simulator</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'topology' ? 'active' : ''}`}
            onClick={() => setActiveTab('topology')}
          >
            <Network size={18} />
            <span>Network Segments</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'guardrails' ? 'active' : ''}`}
            onClick={() => setActiveTab('guardrails')}
          >
            <ShieldAlert size={18} />
            <span>Security Guardrails</span>
          </button>

          <button
            className={`nav-item ${activeTab === 'policies' ? 'active' : ''}`}
            onClick={() => setActiveTab('policies')}
          >
            <FileText size={18} />
            <span>Active Policies</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="status-badge">
            <span className={`status-dot ${backendOnline ? '' : 'offline'}`}></span>
            <span>{backendOnline ? 'FastAPI Connected' : 'Local Sandbox Mode'}</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        <header className="content-header">
          <div className="header-title">
            <h2>
              {activeTab === 'simulator' && 'Network Access Simulation & Impact Analysis'}
              {activeTab === 'topology' && 'Network Topology & Critical Assets'}
              {activeTab === 'guardrails' && 'Predefined Security Guardrails'}
              {activeTab === 'policies' && 'Current Baseline Firewall Policies'}
            </h2>
            <p>
              {activeTab === 'simulator' && 'Evaluate proposed firewall rules and detect security policy violations before deployment.'}
              {activeTab === 'topology' && 'Overview of configured corporate subnets and sensitive backend endpoints.'}
              {activeTab === 'guardrails' && 'Hard isolation boundaries enforced independently from firewall rules.'}
              {activeTab === 'policies' && 'Current active allow and default-deny access control rules.'}
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <span className="badge badge-warning">Milestone 1 MVP</span>
            <span className="badge badge-allowed">Python 3.13 + React</span>
          </div>
        </header>

        <div className="content-body">
          {/* TAB 1: POLICY SIMULATOR */}
          {activeTab === 'simulator' && (
            <div>
              {/* Presets Bar */}
              <div className="presets-bar">
                <div className="presets-label">Quick Demonstration Presets:</div>
                <div className="preset-buttons">
                  <button
                    className="btn-preset"
                    onClick={() => loadScenario('risky-hr')}
                  >
                    <AlertTriangle size={15} color="#ef4444" />
                    <span>🚨 Test Risky HR $\rightarrow$ Finance DB Rule</span>
                  </button>
                  <button
                    className="btn-preset"
                    onClick={() => loadScenario('safe-finance')}
                  >
                    <CheckCircle2 size={15} color="#10b981" />
                    <span>✅ Test Permitted Finance $\rightarrow$ Finance DB</span>
                  </button>
                  <button
                    className="btn-preset"
                    onClick={() => loadScenario('denied-jumpbox')}
                  >
                    <XCircle size={15} color="#9ca3af" />
                    <span>⛔ Test Denied HR $\rightarrow$ IT Jumpbox</span>
                  </button>
                  <button
                    className="btn-preset"
                    onClick={() => loadScenario('safe-portal')}
                  >
                    <CheckCircle2 size={15} color="#3b82f6" />
                    <span>🌐 Test Safe Corporate Web Portal</span>
                  </button>
                </div>
              </div>

              {/* Simulation Input Card */}
              <div className="card">
                <h3 className="card-title">
                  <Network size={20} color="#3b82f6" />
                  <span>1. Configure Proposed Connection</span>
                </h3>

                <div className="simulator-grid">
                  <div className="form-group">
                    <label>Source Network Segment:</label>
                    <select
                      className="form-control"
                      value={sourceSegment}
                      onChange={(e) => setSourceSegment(e.target.value)}
                    >
                      {segments.map((seg) => (
                        <option key={seg.id} value={seg.id}>
                          {seg.name} ({seg.cidr})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="form-group">
                    <label>Destination Target Resource:</label>
                    <select
                      className="form-control"
                      value={destinationResource}
                      onChange={(e) => {
                        setDestinationResource(e.target.value);
                        const r = resources.find(item => item.id === e.target.value);
                        if (r) setPort(r.port);
                      }}
                    >
                      {resources.map((res) => (
                        <option key={res.id} value={res.id}>
                          {res.name} ({res.ip}) {res.is_critical ? '⭐ [CRITICAL]' : ''}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="form-group">
                    <label>Port Number:</label>
                    <input
                      type="number"
                      className="form-control"
                      value={port}
                      onChange={(e) => setPort(e.target.value)}
                    />
                  </div>

                  <div className="form-group">
                    <label>Protocol:</label>
                    <select
                      className="form-control"
                      value={protocol}
                      onChange={(e) => setProtocol(e.target.value)}
                    >
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                    </select>
                  </div>
                </div>

                {/* Proposed Rule Configuration Box */}
                <div className="proposed-rule-box">
                  <div
                    className="rule-header-toggle"
                    onClick={() => setHasProposedRule(!hasProposedRule)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <input
                        type="checkbox"
                        checked={hasProposedRule}
                        onChange={(e) => setHasProposedRule(e.target.checked)}
                        style={{ cursor: 'pointer', width: '16px', height: '16px' }}
                      />
                      <strong style={{ fontSize: '0.95rem' }}>Simulate a Proposed Rule Change</strong>
                    </div>
                    <span style={{ fontSize: '0.8rem', color: '#9ca3af' }}>
                      {hasProposedRule ? 'Evaluating with proposed rule' : 'Testing baseline policy only'}
                    </span>
                  </div>

                  {hasProposedRule && (
                    <div className="simulator-grid" style={{ marginTop: '16px', marginBottom: 0 }}>
                      <div className="form-group">
                        <label>Proposed Rule Label:</label>
                        <input
                          type="text"
                          className="form-control"
                          value={proposedRuleName}
                          onChange={(e) => setProposedRuleName(e.target.value)}
                          placeholder="e.g. Allow HR DB Direct Access"
                        />
                      </div>

                      <div className="form-group">
                        <label>Action:</label>
                        <select
                          className="form-control"
                          value={proposedRuleAction}
                          onChange={(e) => setProposedRuleAction(e.target.value)}
                        >
                          <option value="ALLOW">ALLOW</option>
                          <option value="DENY">DENY</option>
                        </select>
                      </div>

                      <div className="form-group">
                        <label>Priority (Lower = Higher precedence):</label>
                        <input
                          type="number"
                          className="form-control"
                          value={proposedRulePriority}
                          onChange={(e) => setProposedRulePriority(e.target.value)}
                          min="1"
                          max="998"
                        />
                      </div>
                    </div>
                  )}
                </div>

                <button
                  className="btn-simulate"
                  onClick={handleSimulate}
                  disabled={loading}
                >
                  <Play size={18} />
                  <span>{loading ? 'Evaluating Policies...' : 'Run Security Impact Simulation'}</span>
                </button>
              </div>

              {/* SIMULATION RESULTS VIEW */}
              {simulationResult && (
                <div>
                  {/* Critical Security Risk Banner */}
                  {simulationResult.risk_detected ? (
                    <div className="risk-banner">
                      <div className="risk-banner-header">
                        <ShieldAlert size={28} color="#ef4444" />
                        <h3>CRITICAL SECURITY VIOLATION FLAGGED</h3>
                      </div>
                      <p style={{ color: '#fecaca', fontSize: '0.95rem', marginBottom: '14px' }}>
                        The proposed change introduces a direct policy breach against enterprise security boundaries.
                        <strong> This change must not be deployed.</strong>
                      </p>

                      {simulationResult.violations.map((violation, idx) => (
                        <div key={idx} className="violation-item">
                          <div className="violation-title">
                            ⚠️ Guardrail {violation.guardrail_id}: {violation.name} [{violation.severity}]
                          </div>
                          <div className="violation-desc">
                            {violation.description}
                          </div>
                          <div className="violation-rationale">
                            <strong>Compliance Impact:</strong> {violation.rationale}
                          </div>
                        </div>
                      ))}

                      <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(0,0,0,0.4)', borderRadius: '6px' }}>
                        <span style={{ fontWeight: '600', color: '#f87171' }}>Platform Recommendation: </span>
                        <span style={{ color: '#ffffff' }}>{simulationResult.recommendation}</span>
                      </div>
                    </div>
                  ) : (
                    <div className="safe-banner">
                      <ShieldCheck size={28} color="#10b981" />
                      <div>
                        <strong style={{ color: '#34d399', fontSize: '1.05rem', display: 'block' }}>
                          No Security Violations Detected
                        </strong>
                        <span style={{ color: '#d1fae5', fontSize: '0.88rem' }}>
                          {simulationResult.recommendation}
                        </span>
                      </div>
                    </div>
                  )}

                  {/* Before vs. After Side-by-Side Comparison */}
                  <div className="card" style={{ marginTop: '24px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                      <h3 className="card-title" style={{ margin: 0 }}>
                        <Layers size={20} color="#3b82f6" />
                        <span>Before vs. After Policy Impact Analysis</span>
                      </h3>

                      <span className={`badge ${
                        simulationResult.change_type === 'ACCESS_GRANTED'
                          ? (simulationResult.risk_detected ? 'badge-critical' : 'badge-allowed')
                          : (simulationResult.change_type === 'ACCESS_REVOKED' ? 'badge-denied' : 'badge-warning')
                      }`}>
                        Delta: {simulationResult.change_type}
                      </span>
                    </div>

                    <div className="comparison-container">
                      {/* Before Card */}
                      <div className={`comparison-card ${simulationResult.current_evaluation.status === 'ALLOWED' ? 'allowed' : 'denied'}`}>
                        <div className="comparison-header">
                          <h4>BEFORE (Current Baseline)</h4>
                          <span className={`badge ${simulationResult.current_evaluation.status === 'ALLOWED' ? 'badge-allowed' : 'badge-denied'}`}>
                            {simulationResult.current_evaluation.status === 'ALLOWED' ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
                            {simulationResult.current_evaluation.status}
                          </span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Matched Policy:</span>
                          <span className="meta-value">{simulationResult.current_evaluation.matched_rule_name}</span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Rule Priority:</span>
                          <span className="meta-value">Priority {simulationResult.current_evaluation.matched_rule_priority}</span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Explanation:</span>
                          <span style={{ fontSize: '0.84rem', color: '#9ca3af' }}>
                            {simulationResult.current_evaluation.explanation}
                          </span>
                        </div>
                      </div>

                      {/* After Card */}
                      <div className={`comparison-card ${
                        simulationResult.risk_detected
                          ? 'denied'
                          : (simulationResult.proposed_evaluation.status === 'ALLOWED' ? 'allowed' : 'denied')
                      }`}>
                        <div className="comparison-header">
                          <h4>AFTER (Proposed Policy)</h4>
                          <span className={`badge ${
                            simulationResult.risk_detected
                              ? 'badge-critical'
                              : (simulationResult.proposed_evaluation.status === 'ALLOWED' ? 'badge-allowed' : 'badge-denied')
                          }`}>
                            {simulationResult.risk_detected ? (
                              <>
                                <AlertTriangle size={13} />
                                CRITICAL RISK
                              </>
                            ) : (
                              simulationResult.proposed_evaluation.status === 'ALLOWED' ? (
                                <><CheckCircle2 size={13} /> ALLOWED</>
                              ) : (
                                <><XCircle size={13} /> DENIED</>
                              )
                            )}
                          </span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Active Rule:</span>
                          <span className="meta-value">{simulationResult.proposed_evaluation.matched_rule_name}</span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Rule Priority:</span>
                          <span className="meta-value">Priority {simulationResult.proposed_evaluation.matched_rule_priority}</span>
                        </div>

                        <div className="meta-row">
                          <span className="meta-label">Security Evaluation:</span>
                          <span style={{ fontSize: '0.84rem', color: simulationResult.risk_detected ? '#fca5a5' : '#9ca3af' }}>
                            {simulationResult.risk_detected
                              ? 'Traffic is allowed by the proposed rule, but rejected by Independent Security Guardrail SG-01.'
                              : simulationResult.proposed_evaluation.explanation
                            }
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: NETWORK TOPOLOGY */}
          {activeTab === 'topology' && (
            <div>
              <div className="card">
                <h3 className="card-title">
                  <Network size={20} color="#3b82f6" />
                  <span>Configured Network Segments</span>
                </h3>

                <div className="topology-grid">
                  {segments.map((seg) => (
                    <div key={seg.id} className="segment-card">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <strong style={{ fontSize: '1rem' }}>{seg.name}</strong>
                        <span className="segment-badge">{seg.cidr}</span>
                      </div>
                      <div style={{ fontSize: '0.8rem', color: '#60a5fa' }}>
                        Zone: {seg.security_zone}
                      </div>
                      <p style={{ fontSize: '0.85rem', color: '#9ca3af' }}>
                        {seg.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="card">
                <h3 className="card-title">
                  <Database size={20} color="#3b82f6" />
                  <span>Destination Resources & Sensitive Endpoints</span>
                </h3>

                <div className="topology-grid">
                  {resources.map((res) => (
                    <div key={res.id} className="segment-card" style={res.is_critical ? { borderColor: '#ef4444' } : {}}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <strong style={{ fontSize: '1rem' }}>{res.name}</strong>
                        {res.is_critical && (
                          <span className="badge badge-critical">⭐ Critical Asset</span>
                        )}
                      </div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#93c5fd' }}>
                        {res.ip} : {res.port} ({res.protocol})
                      </div>
                      <p style={{ fontSize: '0.85rem', color: '#9ca3af' }}>
                        {res.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: SECURITY GUARDRAILS */}
          {activeTab === 'guardrails' && (
            <div className="card">
              <h3 className="card-title">
                <ShieldAlert size={20} color="#ef4444" />
                <span>Enterprise Security Guardrails & Hard Boundaries</span>
              </h3>
              <p style={{ color: '#9ca3af', fontSize: '0.9rem', marginBottom: '20px' }}>
                Guardrails represent absolute compliance and security constraints. Even if an engineer writes an
                <code style={{ color: '#60a5fa', margin: '0 4px' }}>ALLOW</code> firewall rule,
                NetImpact intercepts and blocks it if it breaches these guardrails.
              </p>

              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Guardrail ID</th>
                    <th>Name</th>
                    <th>Forbidden Source</th>
                    <th>Protected Destination</th>
                    <th>Severity</th>
                    <th>Regulatory Rationale</th>
                  </tr>
                </thead>
                <tbody>
                  {guardrails.map((g) => (
                    <tr key={g.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: '#60a5fa' }}>{g.id}</td>
                      <td><strong>{g.name}</strong></td>
                      <td><code>{g.forbidden_source}</code></td>
                      <td><code>{g.forbidden_destination}</code></td>
                      <td>
                        <span className={`badge ${g.severity === 'CRITICAL' ? 'badge-critical' : 'badge-warning'}`}>
                          {g.severity}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.82rem', color: '#9ca3af' }}>{g.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 4: ACTIVE BASELINE POLICIES */}
          {activeTab === 'policies' && (
            <div className="card">
              <h3 className="card-title">
                <FileText size={20} color="#3b82f6" />
                <span>Current Active Firewall Policies</span>
              </h3>
              <p style={{ color: '#9ca3af', fontSize: '0.9rem', marginBottom: '20px' }}>
                Rules are evaluated in ascending priority order (lowest number first). The first rule that matches a packet
                dictates the action. Unmatched traffic falls through to Rule 999 (Default Deny).
              </p>

              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Priority</th>
                    <th>Rule ID</th>
                    <th>Rule Label</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.map((p) => (
                    <tr key={p.id}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: '#93c5fd' }}>
                        #{p.priority}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{p.id}</td>
                      <td><strong>{p.name}</strong></td>
                      <td><code>{p.source_segment}</code></td>
                      <td><code>{p.destination_resource}</code></td>
                      <td>{p.port !== null ? p.port : 'ANY'}</td>
                      <td>{p.protocol}</td>
                      <td>
                        <span className={`badge ${p.action === 'ALLOW' ? 'badge-allowed' : 'badge-denied'}`}>
                          {p.action}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
