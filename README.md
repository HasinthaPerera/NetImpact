# NetImpact
> **Network Change Impact and Security Risk Analysis Platform** (Milestone 1 MVP)

NetImpact is a pre-flight validation platform designed for network and security engineers. It simulates proposed access control lists (ACLs) and firewall rule modifications in software, evaluates the before-and-after connectivity state, and catches security compliance breaches (such as unauthorized HR access to sensitive financial databases) **before** changes are deployed to live networks.

---

## ⚠️ Important Project Scope & Limitations

* **Simulation MVP**: NetImpact is an algorithmic policy simulation and risk analysis tool. It is **NOT** a physical router emulator or production network packet sniffer.
* **Scope**: It models network segments, resources, and access control rules using structured JSON policies. It does not parse live proprietary router firmware configs (e.g., Cisco IOS, Juniper Junos) directly in Milestone 1.
* **Safe & Non-Intrusive**: NetImpact performs zero live network probing, port scanning, or offensive security actions.

---

## 🛠️ Architecture & Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend** | React 18 + Vite | Modern dashboard with sidebar navigation, simulation sandbox & before/after delta views |
| **Backend** | Python 3.13 + FastAPI | High-performance REST API with Pydantic data validation |
| **Engine** | Python Policy Engine | Rule priority evaluation with strict default-deny and independent security guardrails |
| **Testing** | Pytest + HTTPX | Automated test suite validating permitted, denied, and risky scenarios |
| **Data** | Local JSON Store | Segments (`HR`, `Finance`, `IT`), sensitive assets (`Finance Core DB`), and guardrails |

---

## 📂 Project Directory Structure

```text
NetImpact/
├── .gitignore                   # Ignores Python (.venv) and Node (node_modules) artifacts
├── README.md                    # Project documentation and setup guide
├── backend/
│   ├── requirements.txt         # FastAPI, Uvicorn, Pydantic, Pytest, HTTPX
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI endpoints & CORS configuration
│   │   ├── models.py            # Pydantic schemas (Segments, Rules, Guardrails)
│   │   ├── policy_engine.py     # Rule evaluation & independent guardrail checker
│   │   └── data/
│   │       ├── network_segments.json  # HR, Finance, IT subnets & Finance DB
│   │       ├── current_policies.json  # Active baseline rules with default-deny
│   │       └── security_rules.json    # Security guardrails (e.g., SG-01)
│   └── tests/
│       ├── __init__.py
│       └── test_policy_engine.py      # Automated Pytest suite
└── frontend/
    ├── package.json
    ├── vite.config.js           # Vite dev server with /api proxy to FastAPI
    ├── index.html
    └── src/
        ├── main.jsx
        ├── index.css            # Custom responsive dashboard stylesheet
        └── App.jsx              # Main dashboard with sidebar & interactive simulator
```

---

## 🚀 Setup & Execution Guide (Windows PowerShell)

Follow these steps step-by-step using Windows PowerShell in the root `NetImpact` folder.

### 1. Prerequisites
Ensure you have Python and Node.js installed:
```powershell
py --version
node -v
npm -v
```

---

### 2. Backend Setup & Running

#### Step A: Create and activate a Python virtual environment
```powershell
# Inside c:\Users\ASUS\Desktop\NetImpact
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(Note: If PowerShell shows an Execution Policy error when activating, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and re-run).*

#### Step B: Install Backend Dependencies
```powershell
py -m pip install --upgrade pip
py -m pip install -r backend\requirements.txt
```

#### Step C: Run Automated Tests
```powershell
py -m pytest backend\tests -v
```

#### Step D: Start the FastAPI Backend Server
```powershell
cd backend
py -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
* **API Documentation (Swagger UI)**: Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in your browser.
* **Health Check**: Open [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health).

---

### 3. Frontend Setup & Running

Open a **second** Windows PowerShell terminal:

```powershell
# Navigate to the frontend directory
cd c:\Users\ASUS\Desktop\NetImpact\frontend

# Install dependencies
npm install

# Start the Vite development server
npm run dev
```

* Open your browser at **[http://localhost:5173](http://localhost:5173)** to access the NetImpact dashboard.

---

## 🧪 Key Scenarios to Demonstrate in Milestone 1

1. **🚨 Proposed Risky Change (HR to Finance Core Database)**:
   * **Source**: `Human Resources Segment (10.10.1.0/24)`
   * **Destination**: `Finance Core Database (10.10.2.50:5432)`
   * **Proposed Rule**: `Action = ALLOW, Priority = 15`
   * **Impact**:
     * Current Baseline: ⛔ **DENIED** (Default Deny Rule 999)
     * Proposed State: 🟢 **ALLOWED** by proposed rule
     * **Security Guardrail Alert**: 🚨 **CRITICAL RISK DETECTED (Guardrail SG-01)**. Segregation of duties violation (SOC2 / PCI-DSS). Deployment rejected.

2. **✅ Baseline Permitted Access (Finance to Finance Database)**:
   * **Source**: `Finance Segment (10.10.2.0/24)`
   * **Destination**: `Finance Core Database (10.10.2.50:5432)`
   * **Result**: ✅ **ALLOWED** under Rule `RULE-020` (Priority 20). Safe.

3. **⛔ Baseline Denied Access (HR to IT Management Jumpbox)**:
   * **Source**: `HR Segment`
   * **Destination**: `IT Management Jumpbox (10.10.3.10:22)`
   * **Result**: ⛔ **DENIED** under Rule `RULE-999` (Default Deny).
