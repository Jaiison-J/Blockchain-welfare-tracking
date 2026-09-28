/**
 * Blockchain-Based Welfare Scheme Distribution Tracking System
 * 
 * Language: Standard JavaScript (ES6+)
 * Cryptography: SHA-256 via Web Crypto API (with standalone JS fallback)
 * Storage: HTML5 Web Storage (localStorage)
 */

// ============================================================================
// 1. CRYPTOGRAPHIC HASHING ENGINE (SHA-256)
// ============================================================================

/**
 * Standard pure JavaScript implementation of SHA-256 (FIPS 180-4)
 * Used as a fallback when Web Crypto API is unavailable in iframe environments.
 */
function pureJsSha256(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const lengthProperty = 'length';
  let i, j;
  let result = '';

  const words = [];
  const asciiBitLength = ascii[lengthProperty] * 8;

  let hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  let composite = ascii + '\x80';
  while (composite[lengthProperty] % 64 - 56) composite += '\x00';
  for (i = 0; i < composite[lengthProperty]; i++) {
    j = composite.charCodeAt(i);
    words[i >> 2] |= j << ((3 - (i % 4)) * 8);
  }
  words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
  words[words[lengthProperty]] = asciiBitLength;

  for (j = 0; j < words[lengthProperty];) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash;
    hash = hash.slice(0, 8);

    for (i = 0; i < 64; i++) {
      const i2 = i + j;
      const w15 = w[i - 15], w2 = w[i - 2];

      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = i < 16 ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;

      const s1_h = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const temp1 = (hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ch + k[i] + w[i]) | 0;
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const temp2 = (s1_h + maj) | 0;

      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }

    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }

  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

/**
 * Calculates SHA-256 hash using the Web Crypto API, falling back to pure JavaScript.
 * @param {string} message - String data to hash
 * @returns {Promise<string>} Hexadecimal SHA-256 digest
 */
async function calculateSHA256(message) {
  if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(message);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      console.warn('Web Crypto API failed, using JS fallback:', e);
    }
  }
  return pureJsSha256(message);
}

// ============================================================================
// 2. BLOCK & BLOCKCHAIN ARCHITECTURE
// ============================================================================

/**
 * Represents a single Block in the Welfare Blockchain.
 */
class Block {
  /**
   * @param {number} index - Position of the block in chain
   * @param {string} timestamp - Time block was minted
   * @param {Object|string} data - Welfare transaction details or genesis note
   * @param {string} previousHash - SHA-256 hash of previous block
   * @param {string} [hash=''] - Stored SHA-256 hash of this block
   */
  constructor(index, timestamp, data, previousHash = '', hash = '') {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.previousHash = previousHash;
    this.hash = hash;
  }

  /**
   * Cryptographically computes the SHA-256 hash of the block's contents.
   * @returns {Promise<string>}
   */
  async computeHash() {
    const serializedData = typeof this.data === 'object' ? JSON.stringify(this.data) : String(this.data);
    const payload = `${this.index}|${this.timestamp}|${serializedData}|${this.previousHash}`;
    return await calculateSHA256(payload);
  }
}

/**
 * Manages the Welfare Scheme Distribution Blockchain Ledger.
 */
class WelfareBlockchain {
  constructor() {
    this.chain = [];
    this.storageKey = 'welfare_blockchain_v1';
    this.backupGenuineChain = null; // Used to restore genuine chain after a tampering demo
  }

  /**
   * Initializes the blockchain by reading from localStorage or minting the Genesis block.
   */
  async init() {
    const stored = localStorage.getItem(this.storageKey);
    if (stored) {
      try {
        const rawBlocks = JSON.parse(stored);
        if (Array.isArray(rawBlocks) && rawBlocks.length > 0) {
          this.chain = rawBlocks.map(
            b => new Block(b.index, b.timestamp, b.data, b.previousHash, b.hash)
          );
          return;
        }
      } catch (err) {
        console.error('Error parsing stored blockchain, re-initializing genesis block:', err);
      }
    }
    // Otherwise create Genesis block
    await this.createGenesisBlock();
  }

  /**
   * Mints the foundational Genesis Block (Block #0).
   */
  async createGenesisBlock() {
    const genesisBlock = new Block(
      0,
      new Date().toISOString(),
      {
        message: 'Genesis Block - Welfare Distribution System',
        scheme: 'System Root Trust Anchor',
        department: 'Government Blockchain Gateway',
        beneficiary: 'System Initiator',
        amount: 0,
        transactionId: 'TX-GENESIS-0000',
        remarks: 'Genesis anchor initialized for welfare scheme ledger'
      },
      '0'
    );
    genesisBlock.hash = await genesisBlock.computeHash();
    this.chain = [genesisBlock];
    this.saveToStorage();
  }

  /**
   * Returns the most recent block in the chain.
   */
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  /**
   * Adds a new welfare distribution transaction block to the chain.
   * @param {Object} transactionData - Transaction details
   */
  async addDistribution(transactionData) {
    const latestBlock = this.getLatestBlock();
    const newIndex = latestBlock.index + 1;
    const timestamp = new Date().toISOString();

    const newBlock = new Block(
      newIndex,
      timestamp,
      transactionData,
      latestBlock.hash
    );

    newBlock.hash = await newBlock.computeHash();
    this.chain.push(newBlock);
    this.saveToStorage();
    return newBlock;
  }

  /**
   * Verifies the cryptographic integrity of the entire chain.
   * Checks:
   * 1. Every block's stored hash matches its recalculated hash.
   * 2. Every block's previousHash matches the preceding block's hash.
   */
  async verifyChain() {
    const logs = [];
    let isValid = true;
    let failedIndex = null;
    let failureReason = null;

    for (let i = 0; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const recalculatedHash = await currentBlock.computeHash();

      // Check #1: Does data match the stored hash?
      if (currentBlock.hash !== recalculatedHash) {
        isValid = false;
        failedIndex = i;
        failureReason = `Block #${i} data has been tampered with! Stored hash (${currentBlock.hash.substring(0, 10)}...) does not match recalculated hash (${recalculatedHash.substring(0, 10)}...).`;
        logs.push({
          index: i,
          status: 'tampered',
          message: failureReason,
          storedHash: currentBlock.hash,
          recalculatedHash: recalculatedHash
        });
        break;
      }

      // Check #2: Does previousHash link correctly to the previous block?
      if (i > 0) {
        const previousBlock = this.chain[i - 1];
        if (currentBlock.previousHash !== previousBlock.hash) {
          isValid = false;
          failedIndex = i;
          failureReason = `Block #${i} previousHash pointer is broken! Points to ${currentBlock.previousHash.substring(0, 10)}..., but Block #${i - 1} hash is ${previousBlock.hash.substring(0, 10)}...`;
          logs.push({
            index: i,
            status: 'tampered',
            message: failureReason,
            previousHash: currentBlock.previousHash,
            expectedPreviousHash: previousBlock.hash
          });
          break;
        }
      } else {
        // Genesis block must have previousHash "0"
        if (currentBlock.previousHash !== '0') {
          isValid = false;
          failedIndex = 0;
          failureReason = `Genesis Block (Block #0) previousHash must be "0", but found: ${currentBlock.previousHash}`;
          logs.push({
            index: 0,
            status: 'tampered',
            message: failureReason
          });
          break;
        }
      }

      logs.push({
        index: i,
        status: 'valid',
        message: `Block #${i} is cryptographically valid. Hash & link match.`,
        hash: currentBlock.hash
      });
    }

    return {
      isValid,
      failedIndex,
      failureReason,
      logs
    };
  }

  /**
   * Demonstration feature for lab evaluation:
   * Tampers with a block's data in memory without updating its hash.
   * This immediately demonstrates why tampering fails verification!
   */
  tamperBlock(blockIndex, newAmount, newBeneficiary) {
    if (this.chain.length <= 1 && blockIndex !== 0) {
      return false;
    }
    const target = this.chain[blockIndex];
    if (!target) return false;

    // Backup genuine chain first so we can restore later
    if (!this.backupGenuineChain) {
      this.backupGenuineChain = JSON.parse(JSON.stringify(this.chain));
    }

    // Modify data maliciously
    if (typeof target.data === 'object') {
      if (newAmount !== undefined) {
        target.data.amount = Number(newAmount);
      }
      if (newBeneficiary) {
        target.data.beneficiary = newBeneficiary;
        target.data.beneficiaryName = newBeneficiary;
      }
      target.data.tampered = true;
      target.data.tamperNote = '⚠️ UNAUTHORIZED LAB TAMPERING DETECTED';
    } else {
      target.data = target.data + ' [MALICIOUS MODIFICATION]';
    }

    // Do NOT recalculate hash! This is what catches the fraud!
    return true;
  }

  /**
   * Restores the genuine chain state after a tampering demo.
   */
  async restoreGenuineChain() {
    if (this.backupGenuineChain) {
      this.chain = this.backupGenuineChain.map(
        b => new Block(b.index, b.timestamp, b.data, b.previousHash, b.hash)
      );
      this.backupGenuineChain = null;
      this.saveToStorage();
      return true;
    }
    // If no backup was saved, reload from localStorage or re-mint
    const stored = localStorage.getItem(this.storageKey);
    if (stored) {
      const rawBlocks = JSON.parse(stored);
      this.chain = rawBlocks.map(
        b => new Block(b.index, b.timestamp, b.data, b.previousHash, b.hash)
      );
      return true;
    }
    await this.createGenesisBlock();
    return true;
  }

  /**
   * Resets the entire ledger back to only the Genesis block.
   */
  async resetToGenesis() {
    localStorage.removeItem(this.storageKey);
    this.backupGenuineChain = null;
    await this.createGenesisBlock();
  }

  /**
   * Loads 3 sample college demo welfare distribution blocks.
   */
  async loadSampleData() {
    // Sample transactions as specified in requirements:
    // 1. Food Subsidy
    // 2. Student Scholarship
    // 3. Housing Assistance
    const samples = [
      {
        beneficiaryName: 'Ramesh Kumar',
        beneficiaryId: 'BEN-2026-1014',
        schemeName: 'Food Subsidy & Nutrition (PDS)',
        amount: 3500,
        distributionDate: new Date(Date.now() - 86400000 * 3).toISOString().split('T')[0],
        department: 'Dept. of Food & Civil Supplies',
        remarks: 'Subsidized food grain allowance (DBT transfer)',
        transactionId: 'TX-WB-90142',
        isDemo: true
      },
      {
        beneficiaryName: 'Priya Sharma',
        beneficiaryId: 'BEN-2026-2089',
        schemeName: 'Student Higher Education Scholarship',
        amount: 25000,
        distributionDate: new Date(Date.now() - 86400000 * 2).toISOString().split('T')[0],
        department: 'Dept. of Higher Education',
        remarks: 'Merit-cum-means STEM scholarship year 2026',
        transactionId: 'TX-WB-90185',
        isDemo: true
      },
      {
        beneficiaryName: 'Abdul Rahman',
        beneficiaryId: 'BEN-2026-3140',
        schemeName: 'Rural Housing Assistance Scheme',
        amount: 75000,
        distributionDate: new Date(Date.now() - 86400000 * 1).toISOString().split('T')[0],
        department: 'Ministry of Rural Development',
        remarks: 'Phase 1 construction grant for rural pucca house',
        transactionId: 'TX-WB-90230',
        isDemo: true
      }
    ];

    for (const sample of samples) {
      await this.addDistribution(sample);
    }
  }

  /**
   * Saves the chain to browser localStorage.
   */
  saveToStorage() {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(this.chain));
    } catch (e) {
      console.warn('Could not save to localStorage:', e);
    }
  }
}

// ============================================================================
// 3. USER INTERFACE CONTROLLER & EVENT LISTENERS
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Initialize Blockchain
  const blockchain = new WelfareBlockchain();
  await blockchain.init();

  // DOM Elements
  const distributionForm = document.getElementById('distributionForm');
  const distributionDateInput = document.getElementById('distributionDate');
  const blockchainLedgerContainer = document.getElementById('blockchainLedgerContainer');
  const chainLengthBadge = document.getElementById('chainLengthBadge');

  // Dashboard Stat Elements
  const statBeneficiaries = document.getElementById('statBeneficiaries');
  const statDistributions = document.getElementById('statDistributions');
  const statTotalAmount = document.getElementById('statTotalAmount');
  const statBlockCount = document.getElementById('statBlockCount');
  const statStatusText = document.getElementById('statStatusText');
  const statStatusDetail = document.getElementById('statStatusDetail');
  const statusCardContainer = document.getElementById('statusCardContainer');
  const globalChainStatusBadge = document.getElementById('globalChainStatusBadge');
  const globalChainStatusText = document.getElementById('globalChainStatusText');
  const statusDot = document.getElementById('statusDot');

  // Lab Testing & Verification Elements
  const headerVerifyBtn = document.getElementById('headerVerifyBtn');
  const verifyLedgerBtn = document.getElementById('verifyLedgerBtn');
  const tamperDemoBtn = document.getElementById('tamperDemoBtn');
  const restoreChainBtn = document.getElementById('restoreChainBtn');
  const clearAllBtn = document.getElementById('clearAllBtn');
  const loadSampleDataBtn = document.getElementById('loadSampleDataBtn');

  // Verification Results Panel
  const verificationResultPanel = document.getElementById('verificationResultPanel');
  const verificationBadge = document.getElementById('verificationBadge');
  const verificationTimestamp = document.getElementById('verificationTimestamp');
  const verificationSummary = document.getElementById('verificationSummary');
  const verificationLogList = document.getElementById('verificationLogList');

  // Live Hash Tester
  const liveHashInput = document.getElementById('liveHashInput');
  const liveHashOutput = document.getElementById('liveHashOutput');

  // Toast Notification
  const toastNotification = document.getElementById('toastNotification');
  const toastMessage = document.getElementById('toastMessage');
  const toastIcon = document.getElementById('toastIcon');
  const toastCloseBtn = document.getElementById('toastCloseBtn');

  // Modal
  const blockModal = document.getElementById('blockModal');
  const modalTitle = document.getElementById('modalTitle');
  const modalJsonContent = document.getElementById('modalJsonContent');
  const modalCloseBtn = document.getElementById('modalCloseBtn');
  const modalDoneBtn = document.getElementById('modalDoneBtn');
  const modalCopyBtn = document.getElementById('modalCopyBtn');

  // Search DOM Elements
  const headerSearchBtn = document.getElementById('headerSearchBtn');
  const searchSection = document.getElementById('searchSection');
  const ledgerSearchInput = document.getElementById('ledgerSearchInput');
  const clearSearchBtn = document.getElementById('clearSearchBtn');
  const searchFilterSelect = document.getElementById('searchFilterSelect');
  const searchResultsCount = document.getElementById('searchResultsCount');
  const searchResultsList = document.getElementById('searchResultsList');
  const quickTagBtns = document.querySelectorAll('.quick-tag-btn');

  // Set default date in form to today
  if (distributionDateInput) {
    distributionDateInput.value = new Date().toISOString().split('T')[0];
  }

  // Helper: Show Toast
  function showToast(message, type = 'success') {
    if (!toastNotification) return;
    toastNotification.className = `toast-notification ${type}`;
    toastMessage.textContent = message;
    toastIcon.textContent = type === 'success' ? '✅' : type === 'error' ? '🚨' : 'ℹ️';
    toastNotification.classList.remove('hidden');

    clearTimeout(toastNotification._timer);
    toastNotification._timer = setTimeout(() => {
      toastNotification.classList.add('hidden');
    }, 5500);
  }

  if (toastCloseBtn) {
    toastCloseBtn.addEventListener('click', () => {
      toastNotification.classList.add('hidden');
    });
  }

  // ============================================================================
  // 4. RENDERING & UI UPDATES
  // ============================================================================

  /**
   * Refreshes all statistics on the top dashboard cards.
   */
  async function updateDashboard(verificationResult) {
    const chain = blockchain.chain;
    const txBlocks = chain.filter(b => b.index > 0);

    // Unique beneficiaries
    const uniqueBeneficiaries = new Set();
    let totalAmount = 0;

    txBlocks.forEach(b => {
      if (b.data && typeof b.data === 'object') {
        const id = b.data.beneficiaryId || b.data.beneficiaryName;
        if (id) uniqueBeneficiaries.add(id);
        const amt = Number(b.data.amount) || 0;
        totalAmount += amt;
      }
    });

    statBeneficiaries.textContent = uniqueBeneficiaries.size;
    statDistributions.textContent = txBlocks.length;
    statTotalAmount.textContent = '₹' + totalAmount.toLocaleString('en-IN');
    statBlockCount.textContent = chain.length;
    chainLengthBadge.textContent = `Chain Length: ${chain.length} ${chain.length === 1 ? 'Block' : 'Blocks'}`;

    // Status reflection
    const isValid = verificationResult ? verificationResult.isValid : true;

    if (isValid) {
      statStatusText.textContent = 'Valid';
      statStatusDetail.textContent = 'All SHA-256 hashes & links verified';
      statusCardContainer.classList.remove('tampered');

      globalChainStatusText.textContent = 'Blockchain Valid';
      globalChainStatusBadge.classList.remove('tampered');
      statusDot.className = 'status-dot valid';
    } else {
      statStatusText.textContent = 'Tampered';
      statStatusDetail.textContent = 'Cryptographic linkage broken!';
      statusCardContainer.classList.add('tampered');

      globalChainStatusText.textContent = 'Blockchain Tampered';
      globalChainStatusBadge.classList.add('tampered');
      statusDot.className = 'status-dot tampered';
    }
  }

  /**
   * Renders the visual Blockchain Ledger.
   */
  function renderLedger(verificationResult) {
    if (!blockchainLedgerContainer) return;
    blockchainLedgerContainer.innerHTML = '';

    const failedIndex = verificationResult && !verificationResult.isValid ? verificationResult.failedIndex : null;

    blockchain.chain.forEach((block, index) => {
      const isGenesis = block.index === 0;
      const isTampered = failedIndex === index || (block.data && block.data.tampered);

      // Wrapper
      const blockWrapper = document.createElement('div');
      blockWrapper.className = 'block-card-wrapper';

      // Connective arrow between blocks (except for Block 0)
      if (index > 0) {
        const linkConnector = document.createElement('div');
        linkConnector.className = 'chain-link-arrow-down';
        linkConnector.innerHTML = `
          <div class="chain-connector-line"></div>
          <span class="chain-connector-text">🔗 previousHash links to Block #${index - 1}</span>
          <div class="chain-connector-pointer">▼</div>
        `;
        blockWrapper.appendChild(linkConnector);
      }

      // Block Card
      const card = document.createElement('div');
      card.className = `block-card ${isGenesis ? 'genesis' : ''} ${isTampered ? 'tampered-block' : ''}`;
      card.id = `block-card-${block.index}`;

      // Formatted Date
      let formattedDate = 'N/A';
      try {
        formattedDate = new Date(block.timestamp).toLocaleString();
      } catch (e) {
        formattedDate = block.timestamp;
      }

      // Data extraction
      const data = block.data || {};
      const beneficiary = data.beneficiaryName || data.beneficiary || (isGenesis ? 'Root System' : 'N/A');
      const beneficiaryId = data.beneficiaryId || (isGenesis ? 'GENESIS-0' : 'N/A');
      const scheme = data.schemeName || data.scheme || (isGenesis ? 'Genesis Trust Anchor' : 'N/A');
      const amount = data.amount !== undefined ? Number(data.amount) : 0;
      const department = data.department || (isGenesis ? 'Government Blockchain Gateway' : 'N/A');
      const remarks = data.remarks || '';
      const isDemo = Boolean(data.isDemo);

      card.innerHTML = `
        <div class="block-card-top">
          <div class="block-index-badge">
            <span class="block-num-pill">Block #${block.index}</span>
            ${isGenesis ? '<span class="genesis-tag">Genesis Block</span>' : ''}
            ${isDemo ? '<span class="demo-data-tag">DEMO DATA</span>' : ''}
            ${isTampered ? '<span class="tampered-tag">⚠️ TAMPERED</span>' : ''}
          </div>
          <div class="block-timestamp">
            <svg style="width:14px;height:14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="12 6 12 12 16 14"></polyline>
            </svg>
            ${formattedDate}
          </div>
        </div>

        <div class="block-body-grid">
          <div class="block-data-field">
            <span class="data-label">Beneficiary</span>
            <span class="data-value">${escapeHtml(beneficiary)}</span>
            <span style="font-size:0.75rem;color:var(--text-muted);">${escapeHtml(beneficiaryId)}</span>
          </div>

          <div class="block-data-field">
            <span class="data-label">Welfare Scheme</span>
            <span class="data-value">${escapeHtml(scheme)}</span>
            <span style="font-size:0.75rem;color:var(--text-muted);">${escapeHtml(department)}</span>
          </div>

          <div class="block-data-field">
            <span class="data-label">Amount Disbursed</span>
            <span class="data-value amount-value">₹${amount.toLocaleString('en-IN')}</span>
            <span style="font-size:0.75rem;color:var(--text-muted);">${remarks ? escapeHtml(remarks) : 'Direct Transfer'}</span>
          </div>
        </div>

        <div class="block-crypto-hashes">
          <div class="hash-row">
            <span class="hash-tag">Previous Hash</span>
            <span class="hash-string" title="${block.previousHash}">${block.previousHash}</span>
            <button class="btn btn-ghost btn-sm copy-hash-btn" data-hash="${block.previousHash}" title="Copy Previous Hash">📋</button>
          </div>
          <div class="hash-row current-hash">
            <span class="hash-tag">Current Hash</span>
            <span class="hash-string" title="${block.hash}">${block.hash}</span>
            <button class="btn btn-ghost btn-sm copy-hash-btn" data-hash="${block.hash}" title="Copy Current Hash">📋</button>
          </div>
        </div>

        <div class="block-actions-bar">
          <button class="btn btn-secondary btn-sm inspect-btn" data-index="${block.index}">
            🔍 Inspect Raw JSON
          </button>
        </div>
      `;

      blockWrapper.appendChild(card);
      blockchainLedgerContainer.appendChild(blockWrapper);
    });

    // Attach copy hash handlers
    document.querySelectorAll('.copy-hash-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const hash = btn.getAttribute('data-hash');
        if (hash) {
          navigator.clipboard.writeText(hash).then(() => {
            const originalText = btn.textContent;
            btn.textContent = '✓';
            setTimeout(() => { btn.textContent = originalText; }, 1200);
          }).catch(() => {
            showToast('Hash copied to clipboard', 'info');
          });
        }
      });
    });

    // Attach inspect raw json handlers
    document.querySelectorAll('.inspect-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = Number(btn.getAttribute('data-index'));
        const blk = blockchain.chain[idx];
        if (blk) {
          modalTitle.textContent = `Block #${blk.index} - Raw Cryptographic Object`;
          modalJsonContent.textContent = JSON.stringify(blk, null, 2);
          blockModal.classList.remove('hidden');
        }
      });
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function highlightText(text, query, shouldHighlight) {
    if (!text) return '';
    if (!query || !shouldHighlight) return escapeHtml(text);

    const regex = new RegExp(`(${escapeRegex(query)})`, 'gi');
    return escapeHtml(text).replace(regex, '<span class="search-highlight">$1</span>');
  }

  /**
   * Smoothly scrolls down to the block card in the Blockchain Ledger and applies a pulse highlight.
   */
  function jumpToBlock(blockIndex) {
    const targetElement = document.getElementById(`block-card-${blockIndex}`);
    if (targetElement) {
      targetElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
      targetElement.classList.remove('highlight-pulse');
      void targetElement.offsetWidth; // Trigger reflow
      targetElement.classList.add('highlight-pulse');
      setTimeout(() => {
        targetElement.classList.remove('highlight-pulse');
      }, 2500);
      showToast(`Navigated to Block #${blockIndex} in ledger`, 'info');
    } else {
      const ledgerSec = document.getElementById('ledgerSection');
      if (ledgerSec) ledgerSec.scrollIntoView({ behavior: 'smooth' });
    }
  }

  /**
   * Filters and renders transactions based on Beneficiary Name, Beneficiary ID, or Welfare Scheme.
   */
  function renderSearchResults() {
    if (!searchResultsList || !searchResultsCount) return;

    const query = (ledgerSearchInput ? ledgerSearchInput.value : '').trim().toLowerCase();
    const filter = searchFilterSelect ? searchFilterSelect.value : 'all';

    // Show/hide clear search button
    if (clearSearchBtn) {
      if (query.length > 0) {
        clearSearchBtn.classList.remove('hidden');
      } else {
        clearSearchBtn.classList.add('hidden');
      }
    }

    const txBlocks = blockchain.chain.filter(b => b.index > 0);

    // If chain has no transactions yet
    if (txBlocks.length === 0) {
      searchResultsCount.textContent = 'No welfare transactions recorded yet.';
      searchResultsList.innerHTML = `
        <div class="no-results-box">
          <div class="no-results-icon">📭</div>
          <p>The blockchain currently only contains the Genesis Block.</p>
          <p style="margin-top:0.35rem;font-size:0.8rem;color:var(--text-muted);">
            Add a new welfare distribution using the form above or click "Load Sample Data" to begin querying.
          </p>
        </div>
      `;
      return;
    }

    // Filter matching blocks
    const matches = txBlocks.filter(b => {
      const data = b.data || {};
      const name = (data.beneficiaryName || data.beneficiary || '').toLowerCase();
      const id = (data.beneficiaryId || '').toLowerCase();
      const scheme = (data.schemeName || data.scheme || '').toLowerCase();

      if (!query) return true; // Show all transactions when search input is empty

      if (filter === 'name') {
        return name.includes(query);
      } else if (filter === 'id') {
        return id.includes(query);
      } else if (filter === 'scheme') {
        return scheme.includes(query);
      } else {
        // all fields
        return name.includes(query) || id.includes(query) || scheme.includes(query);
      }
    });

    // Update count label
    if (!query) {
      searchResultsCount.textContent = `Showing all ${matches.length} transaction(s) recorded in ledger`;
    } else {
      const filterLabel = filter === 'name' ? 'Name' : filter === 'id' ? 'ID' : filter === 'scheme' ? 'Scheme' : 'All Fields';
      searchResultsCount.textContent = `Found ${matches.length} matching transaction(s) for "${escapeHtml(query)}" (${filterLabel})`;
    }

    // Render results
    if (matches.length === 0) {
      searchResultsList.innerHTML = `
        <div class="no-results-box">
          <div class="no-results-icon">🔍</div>
          <p>No transactions found matching <strong>"${escapeHtml(query)}"</strong> in ${filter.toUpperCase()}.</p>
          <p style="margin-top:0.35rem;font-size:0.8rem;color:var(--text-muted);">
            Check spelling or try searching by a different field (Beneficiary Name, ID, or Scheme).
          </p>
        </div>
      `;
      return;
    }

    searchResultsList.innerHTML = '';

    matches.forEach(block => {
      const data = block.data || {};
      const rawName = data.beneficiaryName || data.beneficiary || 'N/A';
      const rawId = data.beneficiaryId || 'N/A';
      const rawScheme = data.schemeName || data.scheme || 'N/A';
      const amount = data.amount !== undefined ? Number(data.amount) : 0;
      const department = data.department || 'N/A';
      const date = data.distributionDate || (block.timestamp ? block.timestamp.split('T')[0] : 'N/A');

      const card = document.createElement('div');
      card.className = 'search-result-card';

      // Highlight matching substrings
      const displayName = highlightText(rawName, query, filter === 'all' || filter === 'name');
      const displayId = highlightText(rawId, query, filter === 'all' || filter === 'id');
      const displayScheme = highlightText(rawScheme, query, filter === 'all' || filter === 'scheme');

      card.innerHTML = `
        <div class="result-card-top">
          <span class="result-block-badge">Block #${block.index}</span>
          <span class="result-amount">₹${amount.toLocaleString('en-IN')}</span>
        </div>

        <div class="result-details">
          <div class="result-beneficiary">${displayName} <span style="font-size:0.75rem;font-weight:normal;color:var(--text-muted);">(${displayId})</span></div>
          <div class="result-scheme">${displayScheme}</div>
          <div class="result-meta">Dept: ${escapeHtml(department)} • Date: ${escapeHtml(date)}</div>
          <div class="result-meta" style="font-family:var(--font-mono);font-size:0.7rem;color:var(--primary);word-break:break-all;">
            Hash: ${block.hash.substring(0, 22)}...
          </div>
        </div>

        <div class="result-actions">
          <button class="btn btn-primary btn-sm result-jump-btn" data-index="${block.index}" title="Jump to this block in the Blockchain Ledger">
            🔗 View in Ledger
          </button>
          <button class="btn btn-secondary btn-sm result-inspect-btn" data-index="${block.index}" title="Inspect full cryptographic block data">
            🔍 Inspect JSON
          </button>
        </div>
      `;

      searchResultsList.appendChild(card);
    });

    // Jump to block in ledger with smooth scroll and pulse highlight
    searchResultsList.querySelectorAll('.result-jump-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const index = btn.getAttribute('data-index');
        jumpToBlock(index);
      });
    });

    // Inspect JSON in modal
    searchResultsList.querySelectorAll('.result-inspect-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = Number(btn.getAttribute('data-index'));
        const blk = blockchain.chain[idx];
        if (blk) {
          modalTitle.textContent = `Block #${blk.index} - Raw Cryptographic Object`;
          modalJsonContent.textContent = JSON.stringify(blk, null, 2);
          blockModal.classList.remove('hidden');
        }
      });
    });
  }

  // ============================================================================
  // 5. BLOCKCHAIN VERIFICATION LOGIC
  // ============================================================================

  async function performVerification(showBannerToast = true) {
    const result = await blockchain.verifyChain();

    // Render log items in the verification panel
    if (verificationLogList) {
      verificationLogList.innerHTML = '';
      result.logs.forEach(log => {
        const logItem = document.createElement('div');
        logItem.className = `log-item ${log.status === 'valid' ? 'success' : 'failure'}`;
        logItem.innerHTML = `
          <span class="log-icon">${log.status === 'valid' ? '✅' : '❌'}</span>
          <div class="log-text">
            <strong>${log.status === 'valid' ? `Block #${log.index} Validated` : `TAMPER ALERT at Block #${log.index}`}</strong>
            <p>${log.message}</p>
            ${log.hash ? `<span class="log-hash-crumb">Hash: ${log.hash.substring(0, 24)}...</span>` : ''}
          </div>
        `;
        verificationLogList.appendChild(logItem);
      });
    }

    if (verificationTimestamp) {
      verificationTimestamp.textContent = `Last verified: ${new Date().toLocaleTimeString()}`;
    }

    if (result.isValid) {
      verificationResultPanel.className = 'verification-panel valid';
      verificationBadge.textContent = 'Blockchain Valid';
      verificationBadge.className = 'verification-badge';
      verificationSummary.textContent = `All ${blockchain.chain.length} block(s) verified! Every SHA-256 hash strictly matches its data payload and points to the correct predecessor hash.`;

      if (showBannerToast) {
        showToast(`Verification Passed: All ${blockchain.chain.length} blocks are cryptographically intact.`, 'success');
      }
    } else {
      verificationResultPanel.className = 'verification-panel tampered';
      verificationBadge.textContent = 'Blockchain Tampered';
      verificationBadge.className = 'verification-badge';
      verificationSummary.textContent = `Tampering Detected: ${result.failureReason}`;

      if (showBannerToast) {
        showToast(`Verification Failed: Unauthorized modification detected at Block #${result.failedIndex}!`, 'error');
      }
    }

    await updateDashboard(result);
    renderLedger(result);
    renderSearchResults();

    return result;
  }

  // ============================================================================
  // 6. EVENT LISTENERS
  // ============================================================================

  // Form submission: Add Distribution
  if (distributionForm) {
    distributionForm.addEventListener('submit', async (e) => {
      e.preventDefault();

      const beneficiaryName = document.getElementById('beneficiaryName').value.trim();
      const beneficiaryId = document.getElementById('beneficiaryId').value.trim();
      const schemeName = document.getElementById('schemeName').value;
      const amount = Number(document.getElementById('amount').value);
      const distributionDate = document.getElementById('distributionDate').value;
      const department = document.getElementById('department').value;
      const remarks = document.getElementById('remarks').value.trim();

      if (!beneficiaryName || !beneficiaryId || !schemeName || !amount || !distributionDate || !department) {
        showToast('Please fill in all required fields.', 'error');
        return;
      }

      // Generate random transaction reference id
      const transactionId = `TX-WB-${Math.floor(10000 + Math.random() * 90000)}`;

      const transactionPayload = {
        beneficiaryName,
        beneficiaryId,
        schemeName,
        amount,
        distributionDate,
        department,
        remarks: remarks || 'Welfare Disbursed via Direct Benefit Gateway',
        transactionId,
        isDemo: false
      };

      const newBlock = await blockchain.addDistribution(transactionPayload);

      // Reset form fields except date
      distributionForm.reset();
      distributionDateInput.value = new Date().toISOString().split('T')[0];

      // Refresh UI & Verify
      await performVerification(false);
      showToast(`Block #${newBlock.index} successfully mined & added! SHA-256: ${newBlock.hash.substring(0, 16)}...`, 'success');

      // Scroll into view of newly added block
      setTimeout(() => {
        const el = document.getElementById(`block-card-${newBlock.index}`);
        if (el) {
          el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 100);
    });
  }

  // Header & Section Verify Buttons
  if (headerVerifyBtn) {
    headerVerifyBtn.addEventListener('click', () => performVerification(true));
  }
  if (verifyLedgerBtn) {
    verifyLedgerBtn.addEventListener('click', () => performVerification(true));
  }

  // Demo Tampering Button (For College Lab Evaluation)
  if (tamperDemoBtn) {
    tamperDemoBtn.addEventListener('click', async () => {
      // Ensure we have at least one transaction block to tamper with
      if (blockchain.chain.length <= 1) {
        showToast('Adding sample welfare distributions first to demonstrate tampering...', 'info');
        await blockchain.loadSampleData();
      }

      // Pick Block #1 to tamper
      const targetIndex = 1;
      const targetBlock = blockchain.chain[targetIndex];
      const originalAmount = targetBlock.data && targetBlock.data.amount ? targetBlock.data.amount : 3500;
      const fraudulentAmount = originalAmount + 50000;

      // Tamper: change the amount to +50,000 and modify beneficiary secretly!
      blockchain.tamperBlock(targetIndex, fraudulentAmount, 'Fraudulent Actor (Modified)');

      // Run verification
      const verifyResult = await performVerification(false);

      showToast(`DEMO ATTACK: Block #${targetIndex} was secretly tampered! Amount changed to ₹${fraudulentAmount.toLocaleString('en-IN')}. Verification immediately detected the hash mismatch!`, 'error');

      // Highlight the tampered card
      setTimeout(() => {
        const el = document.getElementById(`block-card-${targetIndex}`);
        if (el) {
          el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 100);
    });
  }

  // Reset / Restore Genuine Chain
  if (restoreChainBtn) {
    restoreChainBtn.addEventListener('click', async () => {
      await blockchain.restoreGenuineChain();
      await performVerification(false);
      showToast('Chain successfully restored to legitimate cryptographic state.', 'success');
    });
  }

  // Reset to Genesis Only
  if (clearAllBtn) {
    clearAllBtn.addEventListener('click', async () => {
      if (confirm('Are you sure you want to reset the ledger back to Genesis Block only? All other distributions will be cleared.')) {
        await blockchain.resetToGenesis();
        await performVerification(false);
        showToast('Ledger reset to Genesis Block.', 'info');
      }
    });
  }

  // Load Sample Data (3 Schemes)
  if (loadSampleDataBtn) {
    loadSampleDataBtn.addEventListener('click', async () => {
      await blockchain.loadSampleData();
      await performVerification(false);
      showToast('3 sample welfare transactions loaded: Food Subsidy, Scholarship, and Housing Assistance.', 'success');
    });
  }

  // Live SHA-256 Hash Playground
  if (liveHashInput && liveHashOutput) {
    const updateLiveHash = async () => {
      const text = liveHashInput.value;
      const hash = await calculateSHA256(text);
      liveHashOutput.textContent = hash;
    };
    liveHashInput.addEventListener('input', updateLiveHash);
    // Initial run
    updateLiveHash();
  }

  // Modal Controls
  if (modalCloseBtn) {
    modalCloseBtn.addEventListener('click', () => blockModal.classList.add('hidden'));
  }
  if (modalDoneBtn) {
    modalDoneBtn.addEventListener('click', () => blockModal.classList.add('hidden'));
  }
  if (blockModal) {
    blockModal.addEventListener('click', (e) => {
      if (e.target === blockModal) blockModal.classList.add('hidden');
    });
  }
  if (modalCopyBtn) {
    modalCopyBtn.addEventListener('click', () => {
      if (modalJsonContent) {
        navigator.clipboard.writeText(modalJsonContent.textContent).then(() => {
          showToast('Raw JSON copied to clipboard', 'info');
        });
      }
    });
  }

  // Search Event Listeners
  if (ledgerSearchInput) {
    ledgerSearchInput.addEventListener('input', () => {
      renderSearchResults();
    });
  }

  if (searchFilterSelect) {
    searchFilterSelect.addEventListener('change', () => {
      renderSearchResults();
    });
  }

  if (clearSearchBtn) {
    clearSearchBtn.addEventListener('click', () => {
      if (ledgerSearchInput) {
        ledgerSearchInput.value = '';
        ledgerSearchInput.focus();
      }
      renderSearchResults();
    });
  }

  if (headerSearchBtn) {
    headerSearchBtn.addEventListener('click', () => {
      if (searchSection) {
        searchSection.scrollIntoView({ behavior: 'smooth' });
      }
      if (ledgerSearchInput) {
        setTimeout(() => ledgerSearchInput.focus(), 300);
      }
    });
  }

  if (quickTagBtns && quickTagBtns.length > 0) {
    quickTagBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const query = btn.getAttribute('data-query');
        if (ledgerSearchInput && query) {
          ledgerSearchInput.value = query;
          renderSearchResults();
          if (searchSection) {
            searchSection.scrollIntoView({ behavior: 'smooth' });
          }
          ledgerSearchInput.focus();
        }
      });
    });
  }

  // Initial Verification & UI Render
  await performVerification(false);
});
