// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BCCA_Healthcare
 * @notice Blockchain-Based Certificateless Conditional Anonymous Authentication
 *         for Healthcare EHR Sharing (Dual-Chain Architecture)
 *
 * @dev Implements the dual-chain design from healthcare_ehr_scheme.md:
 *
 *   HISTORICAL CHAIN  — Immutable, stores verified EHR signature records.
 *                        Every patient EHR upload that passes verification is logged.
 *
 *   EVIDENCE CHAIN    — Stores revocation evidence with Chameleon Hash.
 *                        HA can update evidence content without changing the block hash.
 *
 * The actual ECC signature verification (σ_i · G == gpk_i + h₁·Ppub + h₂·KID_k + h₃·upk_i)
 * is performed off-chain by the Python Flask consensus server (bcca/verify.py).
 * Once verified, the server calls this contract to record the result on-chain.
 *
 * Role constants: 0 = PATIENT, 1 = DOCTOR, 2 = HOSPITAL_ADMIN
 */
contract BCCA_Healthcare {

    // -----------------------------------------------------------------------
    // Access control
    // -----------------------------------------------------------------------

    address public hospitalAdmin;

    modifier onlyAdmin() {
        require(msg.sender == hospitalAdmin, "Only HA can call this");
        _;
    }

    modifier onlyConsensusServer() {
        require(consensusServers[msg.sender], "Only consensus server can call this");
        _;
    }

    // -----------------------------------------------------------------------
    // Roles
    // -----------------------------------------------------------------------

    uint8 constant ROLE_PATIENT = 0;
    uint8 constant ROLE_DOCTOR  = 1;

    // -----------------------------------------------------------------------
    // User Registry
    // -----------------------------------------------------------------------

    struct UserRecord {
        string  pseudoID;      // ID_i  — pseudonym encoding RID ‖ Role
        string  gpk;           // gpk_i = k_i · G  (hex-encoded ECPoint)
        string  upk;           // upk_i = x_i · G  (hex-encoded ECPoint)
        string  E_i;           // E_i   = d_i · G  (hex-encoded ECPoint)
        string  h1_i;          // h_{1,i} scalar (decimal string)
        uint8   role;          // ROLE_PATIENT or ROLE_DOCTOR
        bool    revoked;
        bool    exists;
        uint256 registeredAt;
    }

    mapping(string => UserRecord) private users;   // pseudoID → UserRecord
    string[] public userIDs;                        // list of all pseudonym IDs

    event UserRegistered(string indexed pseudoID, uint8 role, uint256 timestamp);
    event UserRevoked(string indexed pseudoID, uint256 timestamp);

    // -----------------------------------------------------------------------
    // Historical Chain — Verified EHR Signature Records
    // -----------------------------------------------------------------------

    struct EHRRecord {
        string  pseudoID;      // Patient's pseudonym
        string  sigma;         // σ_i  (decimal string)
        string  KID_k;         // KID_{i,k} (hex ECPoint)
        string  ciphertext;    // c_i = m_i ⊕ ek_{i,k}  (hex bytes)
        string  Q_k;           // Q_{i,k} (hex ECPoint)
        uint256 timestamp;     // T_i
        bytes32 blockHash;     // keccak256 of EHR fields for integrity
        bool    exists;
    }

    mapping(bytes32 => EHRRecord) private ehrRecords;   // blockHash → record
    bytes32[] public ehrBlockHashes;                     // ordered chain

    event EHRUploaded(
        string  indexed pseudoID,
        bytes32 indexed blockHash,
        uint256 timestamp
    );

    // -----------------------------------------------------------------------
    // Evidence Chain — Revocation Evidence with Chameleon Hash
    // -----------------------------------------------------------------------

    struct EvidenceRecord {
        string  pseudoID;      // Revoked user's pseudonym
        string  HK_i;          // HK_i = ck_i · G  (hex ECPoint, public hash key)
        string  CH_i;          // Chameleon Hash value  (hex ECPoint)
        string  j_i;           // Salt j_i (decimal string)
        string  credHash;      // keccak256 hex of credential data (commitment)
        string  credData;      // cred_i = {ID, RID_masked, Role, evidence}
        uint256 timestamp;
        bool    active;
    }

    mapping(string => EvidenceRecord) private evidenceChain;  // pseudoID → evidence
    string[] public evidenceIDs;

    event EvidenceAdded(string indexed pseudoID, string CH_i, uint256 timestamp);
    event EvidenceModified(string indexed pseudoID, string CH_i, uint256 timestamp);

    // -----------------------------------------------------------------------
    // Consensus Servers (Blockchain Nodes that verify signatures off-chain)
    // -----------------------------------------------------------------------

    mapping(address => bool) public consensusServers;

    event ConsensusServerAdded(address server);
    event ConsensusServerRemoved(address server);

    // -----------------------------------------------------------------------
    // Audit Log (for HIPAA / GDPR compliance)
    // -----------------------------------------------------------------------

    struct AuditEntry {
        string  actor;         // pseudoID of patient or doctor
        string  action;        // "EHR_UPLOAD", "EHR_ACCESS", "REVOKE", etc.
        string  target;        // target pseudoID or EHR blockHash (hex)
        uint256 timestamp;
    }

    AuditEntry[] private auditLog;

    event AuditLogged(string actor, string action, uint256 timestamp);

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor() {
        hospitalAdmin = msg.sender;
        consensusServers[msg.sender] = true;
    }

    // -----------------------------------------------------------------------
    // Admin functions
    // -----------------------------------------------------------------------

    function addConsensusServer(address server) external onlyAdmin {
        consensusServers[server] = true;
        emit ConsensusServerAdded(server);
    }

    function removeConsensusServer(address server) external onlyAdmin {
        consensusServers[server] = false;
        emit ConsensusServerRemoved(server);
    }

    // -----------------------------------------------------------------------
    // User Registration (called by consensus server after HA issues partial key)
    // -----------------------------------------------------------------------

    function registerUser(
        string calldata pseudoID,
        string calldata gpk,
        string calldata upk,
        string calldata E_i,
        string calldata h1_i,
        uint8           role
    ) external onlyConsensusServer {
        require(!users[pseudoID].exists, "User already registered");
        require(role == ROLE_PATIENT || role == ROLE_DOCTOR, "Invalid role");

        users[pseudoID] = UserRecord({
            pseudoID     : pseudoID,
            gpk          : gpk,
            upk          : upk,
            E_i          : E_i,
            h1_i         : h1_i,
            role         : role,
            revoked      : false,
            exists       : true,
            registeredAt : block.timestamp
        });
        userIDs.push(pseudoID);

        _addAudit(pseudoID, "REGISTER", pseudoID);
        emit UserRegistered(pseudoID, role, block.timestamp);
    }

    function getUser(string calldata pseudoID)
        external view
        returns (string memory gpk, string memory upk, string memory E_i,
                 string memory h1_i, uint8 role, bool revoked, bool exists)
    {
        UserRecord storage u = users[pseudoID];
        return (u.gpk, u.upk, u.E_i, u.h1_i, u.role, u.revoked, u.exists);
    }

    function isRevoked(string calldata pseudoID) external view returns (bool) {
        return users[pseudoID].revoked;
    }

    // -----------------------------------------------------------------------
    // Historical Chain — EHR Upload (called after off-chain verification)
    // -----------------------------------------------------------------------

    /**
     * @notice Store a verified EHR signature record on the Historical Chain.
     * @dev Called by the consensus server (Flask backend) ONLY after
     *      bcca/verify.py confirms the signature σ_i is valid.
     */
    function storeEHRRecord(
        string calldata pseudoID,
        string calldata sigma,
        string calldata KID_k,
        string calldata ciphertext,
        string calldata Q_k,
        uint256         timestamp
    ) external onlyConsensusServer returns (bytes32 blockHash) {
        require(users[pseudoID].exists, "User not registered");
        require(!users[pseudoID].revoked, "User is revoked");

        // Compute block hash (links this record to the chain)
        bytes32 prevHash = ehrBlockHashes.length > 0
            ? ehrBlockHashes[ehrBlockHashes.length - 1]
            : bytes32(0);

        blockHash = keccak256(abi.encodePacked(
            pseudoID, sigma, KID_k, ciphertext, Q_k,
            timestamp, prevHash, block.number
        ));

        require(!ehrRecords[blockHash].exists, "Duplicate record");

        ehrRecords[blockHash] = EHRRecord({
            pseudoID   : pseudoID,
            sigma      : sigma,
            KID_k      : KID_k,
            ciphertext : ciphertext,
            Q_k        : Q_k,
            timestamp  : timestamp,
            blockHash  : blockHash,
            exists     : true
        });
        ehrBlockHashes.push(blockHash);

        _addAudit(pseudoID, "EHR_UPLOAD", _bytes32ToHex(blockHash));
        emit EHRUploaded(pseudoID, blockHash, block.timestamp);
        return blockHash;
    }

    function getEHRRecord(bytes32 blockHash)
        external view
        returns (
            string memory pseudoID,
            string memory sigma,
            string memory KID_k,
            string memory ciphertext,
            string memory Q_k,
            uint256 timestamp,
            bool exists
        )
    {
        EHRRecord storage r = ehrRecords[blockHash];
        return (r.pseudoID, r.sigma, r.KID_k, r.ciphertext, r.Q_k, r.timestamp, r.exists);
    }

    /// @notice Returns list of EHR block hashes (to query the chain)
    function getEHRChainLength() external view returns (uint256) {
        return ehrBlockHashes.length;
    }

    /// @notice Get EHR records for a specific patient pseudonym
    function getPatientEHRs(string calldata pseudoID)
        external view
        returns (bytes32[] memory hashes)
    {
        uint256 count = 0;
        for (uint256 i = 0; i < ehrBlockHashes.length; i++) {
            if (_strEq(ehrRecords[ehrBlockHashes[i]].pseudoID, pseudoID)) {
                count++;
            }
        }
        hashes = new bytes32[](count);
        uint256 j = 0;
        for (uint256 i = 0; i < ehrBlockHashes.length; i++) {
            if (_strEq(ehrRecords[ehrBlockHashes[i]].pseudoID, pseudoID)) {
                hashes[j++] = ehrBlockHashes[i];
            }
        }
    }

    // -----------------------------------------------------------------------
    // Audit Log — Doctor accessing EHR
    // -----------------------------------------------------------------------

    function logEHRAccess(
        string calldata doctorPseudoID,
        string calldata patientPseudoID,
        string calldata blockHashHex
    ) external onlyConsensusServer {
        require(users[doctorPseudoID].role == ROLE_DOCTOR, "Accessor must be a doctor");
        require(!users[doctorPseudoID].revoked, "Doctor is revoked");
        _addAudit(doctorPseudoID, "EHR_ACCESS", blockHashHex);
    }

    // -----------------------------------------------------------------------
    // Evidence Chain — Revocation (Algorithm 9)
    // -----------------------------------------------------------------------

    /**
     * @notice Add a revocation evidence entry to the Evidence Chain.
     *         CH_i value serves as the immutable block identifier.
     *         Content can be updated by HA (Algorithm 10) via chameleon hash.
     */
    function addEvidenceEntry(
        string calldata pseudoID,
        string calldata HK_i,
        string calldata CH_i,
        string calldata j_i,
        string calldata credData
    ) external onlyAdmin {
        require(users[pseudoID].exists, "User not registered");

        bytes32 credHash = keccak256(bytes(credData));

        evidenceChain[pseudoID] = EvidenceRecord({
            pseudoID  : pseudoID,
            HK_i      : HK_i,
            CH_i      : CH_i,
            j_i       : j_i,
            credHash  : _bytes32ToHex(credHash),
            credData  : credData,
            timestamp : block.timestamp,
            active    : true
        });
        evidenceIDs.push(pseudoID);

        // Mark user as revoked
        users[pseudoID].revoked = true;

        _addAudit(pseudoID, "REVOKE", pseudoID);
        emit EvidenceAdded(pseudoID, CH_i, block.timestamp);
        emit UserRevoked(pseudoID, block.timestamp);
    }

    /**
     * @notice Modify evidence data (Algorithm 10).
     *         CH_i must remain unchanged — Python verifies chameleon hash property.
     *         HA provides new credData that produces the same CH_i via trapdoor.
     */
    function modifyEvidenceEntry(
        string calldata pseudoID,
        string calldata newCredData,
        string calldata CH_i_check
    ) external onlyAdmin {
        EvidenceRecord storage ev = evidenceChain[pseudoID];
        require(ev.active, "No active evidence for this user");
        // Verify CH_i has not changed (Python-computed, submitted for on-chain check)
        require(_strEq(ev.CH_i, CH_i_check), "CH_i mismatch: chameleon hash property violated");

        bytes32 newCredHash = keccak256(bytes(newCredData));
        ev.credData = newCredData;
        ev.credHash = _bytes32ToHex(newCredHash);

        _addAudit(pseudoID, "MODIFY_EVIDENCE", pseudoID);
        emit EvidenceModified(pseudoID, ev.CH_i, block.timestamp);
    }

    function getEvidenceEntry(string calldata pseudoID)
        external view
        returns (
            string memory HK_i,
            string memory CH_i,
            string memory j_i,
            string memory credData,
            bool active
        )
    {
        EvidenceRecord storage ev = evidenceChain[pseudoID];
        return (ev.HK_i, ev.CH_i, ev.j_i, ev.credData, ev.active);
    }

    // -----------------------------------------------------------------------
    // Audit Log retrieval
    // -----------------------------------------------------------------------

    function getAuditLogLength() external view returns (uint256) {
        return auditLog.length;
    }

    function getAuditEntry(uint256 index)
        external view
        returns (string memory actor, string memory action,
                 string memory target, uint256 timestamp)
    {
        AuditEntry storage e = auditLog[index];
        return (e.actor, e.action, e.target, e.timestamp);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    function _addAudit(string memory actor, string memory action, string memory target) internal {
        auditLog.push(AuditEntry({
            actor     : actor,
            action    : action,
            target    : target,
            timestamp : block.timestamp
        }));
        emit AuditLogged(actor, action, block.timestamp);
    }

    function _strEq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function _bytes32ToHex(bytes32 b) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory str = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            str[i * 2]     = hexChars[uint8(b[i] >> 4)];
            str[i * 2 + 1] = hexChars[uint8(b[i] & 0x0f)];
        }
        return string(str);
    }
}
