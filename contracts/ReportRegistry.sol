// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ReportRegistry
 * @dev Verifiable Threat Intelligence & Incident Provenance Registry for AegisTrust.
 * Records cryptographic commitments (keccak256 hashes) of investigation reports.
 * Enables decentralized, tamper-evident audit trails without storing PII or raw URLs on-chain.
 */
contract ReportRegistry {
    enum ReportStatus { Submitted, Validated, Disputed, Revoked }

    struct ReportRecord {
        bytes32 reportHash;      // keccak256 of canonical RFC 8785 JSON report
        bytes32 indicatorHash;   // keccak256 of normalized domain/indicator + salt
        address reporter;        // Submitter address
        uint64 timestamp;        // Block timestamp
        uint256 supersedes;      // 0 if original; points to previous report ID on revision
        ReportStatus status;
        uint16 riskScore;        // 0 to 100
    }

    uint256 public nextReportId = 1;
    mapping(uint256 => ReportRecord) public reports;
    mapping(bytes32 => uint256[]) public indicatorToReports;
    mapping(bytes32 => uint256) public reportHashToId;

    event ReportSubmitted(
        uint256 indexed reportId,
        bytes32 indexed reportHash,
        bytes32 indexed indicatorHash,
        address reporter,
        uint16 riskScore
    );

    event ReportStatusUpdated(
        uint256 indexed reportId,
        ReportStatus newStatus,
        address updater
    );

    event ReportDisputed(
        uint256 indexed reportId,
        address disputer,
        string reason
    );

    /**
     * @notice Submits a new threat report cryptographic commitment.
     * @param _reportHash keccak256 hash of the canonical JSON report.
     * @param _indicatorHash Salted keccak256 hash of the investigated domain/indicator.
     * @param _riskScore Computed risk score (0-100).
     */
    function submitReport(
        bytes32 _reportHash,
        bytes32 _indicatorHash,
        uint16 _riskScore
    ) external returns (uint256) {
        require(_reportHash != bytes32(0), "Invalid report hash");
        require(reportHashToId[_reportHash] == 0, "Report hash already registered");

        uint256 id = nextReportId++;
        reports[id] = ReportRecord({
            reportHash: _reportHash,
            indicatorHash: _indicatorHash,
            reporter: msg.sender,
            timestamp: uint64(block.timestamp),
            supersedes: 0,
            status: ReportStatus.Submitted,
            riskScore: _riskScore
        });

        reportHashToId[_reportHash] = id;
        indicatorToReports[_indicatorHash].push(id);

        emit ReportSubmitted(id, _reportHash, _indicatorHash, msg.sender, _riskScore);
        return id;
    }

    /**
     * @notice Submits an updated/revised report that supersedes an existing report.
     */
    function reviseReport(
        uint256 _originalId,
        bytes32 _newReportHash,
        uint16 _newScore
    ) external returns (uint256) {
        require(_originalId > 0 && _originalId < nextReportId, "Original report does not exist");
        require(reports[_originalId].reporter == msg.sender, "Only original reporter can revise");
        require(_newReportHash != bytes32(0), "Invalid report hash");

        uint256 id = nextReportId++;
        bytes32 indHash = reports[_originalId].indicatorHash;

        reports[id] = ReportRecord({
            reportHash: _newReportHash,
            indicatorHash: indHash,
            reporter: msg.sender,
            timestamp: uint64(block.timestamp),
            supersedes: _originalId,
            status: ReportStatus.Submitted,
            riskScore: _newScore
        });

        reportHashToId[_newReportHash] = id;
        indicatorToReports[indHash].push(id);

        emit ReportSubmitted(id, _newReportHash, indHash, msg.sender, _newScore);
        return id;
    }

    /**
     * @notice Allows independent verification of a report hash.
     */
    function verifyReport(bytes32 _reportHash) external view returns (
        bool exists,
        uint256 reportId,
        address reporter,
        uint64 timestamp,
        ReportStatus status,
        uint16 riskScore
    ) {
        uint256 id = reportHashToId[_reportHash];
        if (id == 0) {
            return (false, 0, address(0), 0, ReportStatus.Submitted, 0);
        }
        ReportRecord memory r = reports[id];
        return (true, id, r.reporter, r.timestamp, r.status, r.riskScore);
    }

    /**
     * @notice Disputes a registered report.
     */
    function disputeReport(uint256 _reportId, string calldata _reason) external {
        require(_reportId > 0 && _reportId < nextReportId, "Report does not exist");
        reports[_reportId].status = ReportStatus.Disputed;
        emit ReportDisputed(_reportId, msg.sender, _reason);
        emit ReportStatusUpdated(_reportId, ReportStatus.Disputed, msg.sender);
    }
}
