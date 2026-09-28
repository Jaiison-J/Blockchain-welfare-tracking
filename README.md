# Blockchain-Based Welfare Scheme Distribution Tracking System

A transparent, tamper-evident cryptographic ledger designed to track government welfare scheme disbursements with end-to-end auditability and mathematical integrity verification.

---

## 📌 Project Overview

Traditional public welfare distribution systems rely on centralized databases prone to unauthorized data manipulation, phantom beneficiaries, retroactive record alteration, and lack of public audit trails.

This project implements a decentralized, append-only blockchain ledger using the **NIST FIPS 180-4 SHA-256** cryptographic standard. Each welfare transaction is permanently linked to the previous block via cryptographic hashing, ensuring that any unauthorized tampering is instantaneously detected.

---

## ✨ Key Features

1. **Genesis Block Initialization**:
   - Hardcoded Block #0 with `previousHash = "0"` and initial chain anchor.

2. **Immutable Block Minting**:
   - Records Beneficiary Name, Citizen ID, Welfare Scheme, Disbursed Amount (₹), Department, and Direct Benefit Transfer (DBT) Reference ID.
   - Computes sequential SHA-256 block hash incorporating `Index + Timestamp + Payload + PreviousHash`.

3. **Cryptographic Chain Verification**:
   - Performs dual-stage verification:
     - **Integrity Check**: Recomputes hash from block contents and checks against stored hash.
     - **Linkage Check**: Confirms that `Block(n).previousHash == Block(n-1).hash`.

4. **Interactive Tamper Testing & Attack Simulation**:
   - Allows examiners to simulate malicious attacks by altering beneficiary payouts or citizen details directly in memory.
   - Visually flags the corrupted block and alerts the dashboard immediately.

5. **Search & Real-Time Audit Engine**:
   - Search across Beneficiary Name, Citizen ID, or Scheme Name.
   - One-click jump to inspect raw block JSON structures.

6. **Local Persistence**:
   - Retains minted blocks and audit state across browser refreshes via `localStorage`.

---

## 🛠️ Technology Stack

- **Frontend**: HTML5, CSS3 (Modern Responsive Flexbox/Grid), Vanilla JavaScript (ES6+ Modules)
- **Cryptography**: Web Crypto API (`crypto.subtle.digest('SHA-256')`)
- **Persistence**: HTML5 LocalStorage API
- **Build Tool**: Vite

---

## 🚀 Getting Started

### Prerequisites
- Node.js (version 18 or higher recommended)
- npm or yarn

### Installation & Run

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git

# Navigate into project directory
cd YOUR_REPO

# Install dependencies
npm install

# Start local development server
npm run dev
```

Open your browser at `http://localhost:3000` to interact with the blockchain ledger.
