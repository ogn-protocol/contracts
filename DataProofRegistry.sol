// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title DataProofRegistry
 * @author ORIGIN Protocol
 * @notice The on-chain registry for all creator content registrations.
 *         Stores cryptographic proofs of ownership and timestamps.
 *         Content itself is never stored — only its hash and proof.
 *         This contract is non-upgradable. What is registered here
 *         is permanent and cannot be altered by anyone, including
 *         the protocol team.
 */

contract DataProofRegistry is Ownable, Pausable, ReentrancyGuard {

    // ─────────────────────────────────────────────
    // CONSTANTS
    // ─────────────────────────────────────────────

    // Content type identifiers
    uint8 public constant TYPE_CODE    = 0;
    uint8 public constant TYPE_TEXT    = 1;
    uint8 public constant TYPE_IMAGE   = 2;
    uint8 public constant TYPE_AUDIO   = 3;
    uint8 public constant TYPE_VIDEO   = 4;
    uint8 public constant TYPE_DATASET = 5;

    // v1 only allows code registrations
    // Other types unlock via governance after
    // each category is proven and validated
    uint8 public constant ACTIVE_TYPES_V1 = 0; // only TYPE_CODE active

    // Maximum ContributionScore
    uint256 public constant MAX_SCORE = 1000;

    // Minimum time a wallet must exist before
    // mining rewards activate — anti-sybil
    uint256 public constant MIN_WALLET_AGE_DAYS = 7;

    // ─────────────────────────────────────────────
    // DATA STRUCTURES
    // ─────────────────────────────────────────────

    struct ContentRecord {
        bytes32 contentHash;       // Keccak-256 hash of the content
        address creator;           // Wallet address of the registrant
        uint256 timestamp;         // Block timestamp of registration
        uint8 contentType;         // Content type (0=code in v1)
        bool verified;             // True after validator approval
        bool active;               // False if creator deregistered
        uint256 contributionScore; // 0–1000, set by validators
        bytes32 parentHash;        // Hash of previous version (0x0 if first)
        uint256 walletFirstSeen;   // Timestamp wallet first registered anything
        string metadataURI;        // Optional IPFS URI for off-chain metadata
    }

    struct ValidatorAssessment {
        address validator;
        uint256 proposedScore;
        bool humanCreated;
        bool duplicate;
        uint256 timestamp;
    }

    // ─────────────────────────────────────────────
    // STATE
    // ─────────────────────────────────────────────

    // Primary registry: contentHash => ContentRecord
    mapping(bytes32 => ContentRecord) public registry;

    // All content hashes registered by a creator
    mapping(address => bytes32[]) public creatorRegistrations;

    // All versions of a content piece (parentHash => child hashes)
    mapping(bytes32 => bytes32[]) public contentVersions;

    // Validator assessments per content hash
    mapping(bytes32 => ValidatorAssessment[]) public assessments;

    // Authorized validator contracts
    mapping(address => bool) public authorizedValidators;

    // Authorized content types (governance unlocks new types)
    mapping(uint8 => bool) public activeContentTypes;

    // Track when a wallet first interacted with the protocol
    mapping(address => uint256) public walletFirstSeen;

    // Total registrations counter
    uint256 public totalRegistrations;

    // Total verified registrations counter
    uint256 public totalVerified;

    // Reference to the OGN token contract for reward triggers
    address public ognTokenContract;

    // Reference to the ValidatorPool contract
    address public validatorPoolContract;

    // ─────────────────────────────────────────────
    // EVENTS
    // ─────────────────────────────────────────────

    event ContentRegistered(
        bytes32 indexed contentHash,
        address indexed creator,
        uint8 contentType,
        uint256 timestamp,
        bytes32 parentHash
    );

    event ContentVerified(
        bytes32 indexed contentHash,
        address indexed creator,
        uint256 contributionScore,
        uint256 timestamp
    );

    event ContentDeregistered(
        bytes32 indexed contentHash,
        address indexed creator,
        uint256 timestamp
    );

    event AssessmentSubmitted(
        bytes32 indexed contentHash,
        address indexed validator,
        uint256 proposedScore,
        bool humanCreated,
        bool duplicate
    );

    event ScoreUpdated(
        bytes32 indexed contentHash,
        uint256 oldScore,
        uint256 newScore,
        uint256 timestamp
    );

    event ContentTypeActivated(
        uint8 contentType,
        uint256 timestamp
    );

    event ValidatorAuthorized(
        address indexed validator,
        bool authorized
    );

    // ─────────────────────────────────────────────
    // MODIFIERS
    // ─────────────────────────────────────────────

    modifier onlyValidator() {
        require(
            authorizedValidators[msg.sender],
            "DataProof: caller is not an authorized validator"
        );
        _;
    }

    modifier contentExists(bytes32 contentHash) {
        require(
            registry[contentHash].creator != address(0),
            "DataProof: content not registered"
        );
        _;
    }

    modifier contentActive(bytes32 contentHash) {
        require(
            registry[contentHash].active,
            "DataProof: content has been deregistered"
        );
        _;
    }

    modifier contentTypeAllowed(uint8 contentType) {
        require(
            activeContentTypes[contentType],
            "DataProof: content type not yet active"
        );
        _;
    }

    // ─────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────

    constructor(address initialOwner) Ownable(initialOwner) {
        // v1: only code registrations are active
        activeContentTypes[TYPE_CODE] = true;

        // Other types start locked
        // Governance unlocks them after each category
        // is proven and validated in production
        activeContentTypes[TYPE_TEXT]    = false;
        activeContentTypes[TYPE_IMAGE]   = false;
        activeContentTypes[TYPE_AUDIO]   = false;
        activeContentTypes[TYPE_VIDEO]   = false;
        activeContentTypes[TYPE_DATASET] = false;
    }

    // ─────────────────────────────────────────────
    // CORE: REGISTRATION
    // ─────────────────────────────────────────────

    /**
     * @notice Register a piece of content on-chain.
     *         Content is never uploaded — only its hash and proof.
     *         Once registered, the timestamp is permanent and immutable.
     *
     * @param contentHash   Keccak-256 hash of the content file/repository
     * @param contentType   Type of content (0=code in v1)
     * @param parentHash    Hash of previous version. Use bytes32(0) for new content.
     * @param metadataURI   Optional IPFS URI pointing to off-chain metadata JSON
     */
    function register(
        bytes32 contentHash,
        uint8 contentType,
        bytes32 parentHash,
        string calldata metadataURI
    )
        external
        nonReentrant
        whenNotPaused
        contentTypeAllowed(contentType)
    {
        // Content hash cannot be empty
        require(contentHash != bytes32(0), "DataProof: empty content hash");

        // This exact content hash cannot already be registered
        require(
            registry[contentHash].creator == address(0),
            "DataProof: content already registered"
        );

        // If this is a version update, the parent must exist
        // and must belong to the same creator
        if (parentHash != bytes32(0)) {
            require(
                registry[parentHash].creator == msg.sender,
                "DataProof: parent content not owned by caller"
            );
            require(
                registry[parentHash].active,
                "DataProof: parent content is deregistered"
            );
        }

        // Track when this wallet first interacted with the protocol
        // Used for anti-sybil mining reward eligibility
        if (walletFirstSeen[msg.sender] == 0) {
            walletFirstSeen[msg.sender] = block.timestamp;
        }

        // Create the permanent on-chain record
        registry[contentHash] = ContentRecord({
            contentHash:       contentHash,
            creator:           msg.sender,
            timestamp:         block.timestamp,
            contentType:       contentType,
            verified:          false,       // starts unverified
            active:            true,         // active from registration
            contributionScore: 0,            // score set by validators
            parentHash:        parentHash,
            walletFirstSeen:   walletFirstSeen[msg.sender],
            metadataURI:       metadataURI
        });

        // Add to creator's registration list
        creatorRegistrations[msg.sender].push(contentHash);

        // If this is a version, link it to the parent's version chain
        if (parentHash != bytes32(0)) {
            contentVersions[parentHash].push(contentHash);
        }

        totalRegistrations++;

        emit ContentRegistered(
            contentHash,
            msg.sender,
            contentType,
            block.timestamp,
            parentHash
        );
    }

    // ─────────────────────────────────────────────
    // CORE: DEREGISTRATION
    // ─────────────────────────────────────────────

    /**
     * @notice Creator can deregister their content at any time.
     *         This satisfies GDPR right to erasure — the content
     *         is removed from active licensing eligibility.
     *         The timestamp proof remains (cannot be deleted from
     *         blockchain history) but the content is marked inactive
     *         and excluded from all LicenseMarket pools.
     *
     * @param contentHash Hash of the content to deregister
     */
    function deregister(bytes32 contentHash)
        external
        nonReentrant
        contentExists(contentHash)
        contentActive(contentHash)
    {
        require(
            registry[contentHash].creator == msg.sender,
            "DataProof: caller is not the content creator"
        );

        registry[contentHash].active = false;

        emit ContentDeregistered(contentHash, msg.sender, block.timestamp);
    }

    // ─────────────────────────────────────────────
    // VALIDATOR FUNCTIONS
    // ─────────────────────────────────────────────

    /**
     * @notice Validator submits their assessment of a registered content piece.
     *         Called by the ValidatorPool contract on behalf of individual validators.
     *         Multiple validators assess each piece. Final score is calculated
     *         off-chain (stake-weighted median) and submitted via finalizeScore().
     *
     * @param contentHash   Hash of the content being assessed
     * @param proposedScore Validator's proposed ContributionScore (0–1000)
     * @param humanCreated  Validator's assessment: is this human-created?
     * @param duplicate     Validator's assessment: is this a duplicate?
     */
    function submitAssessment(
        bytes32 contentHash,
        uint256 proposedScore,
        bool humanCreated,
        bool duplicate
    )
        external
        onlyValidator
        nonReentrant
        contentExists(contentHash)
        contentActive(contentHash)
    {
        require(proposedScore <= MAX_SCORE, "DataProof: score exceeds maximum");

        // Prevent a validator submitting multiple assessments
        // for the same content piece
        ValidatorAssessment[] storage existing = assessments[contentHash];
        for (uint256 i = 0; i < existing.length; i++) {
            require(
                existing[i].validator != msg.sender,
                "DataProof: validator already assessed this content"
            );
        }

        assessments[contentHash].push(ValidatorAssessment({
            validator:     msg.sender,
            proposedScore: proposedScore,
            humanCreated:  humanCreated,
            duplicate:     duplicate,
            timestamp:     block.timestamp
        }));

        emit AssessmentSubmitted(
            contentHash,
            msg.sender,
            proposedScore,
            humanCreated,
            duplicate
        );
    }

    /**
     * @notice Finalize the ContributionScore for a content piece
     *         after all validator assessments are collected.
     *         Called by the ValidatorPool contract after calculating
     *         the stake-weighted median off-chain.
     *         Also marks the content as verified.
     *
     * @param contentHash    Hash of the content being finalized
     * @param finalScore     The stake-weighted median score
     * @param humanVerified  True if majority of validators confirmed human creation
     */
    function finalizeScore(
        bytes32 contentHash,
        uint256 finalScore,
        bool humanVerified
    )
        external
        onlyValidator
        nonReentrant
        contentExists(contentHash)
        contentActive(contentHash)
    {
        require(finalScore <= MAX_SCORE, "DataProof: score exceeds maximum");
        require(
            assessments[contentHash].length >= 3,
            "DataProof: minimum 3 validator assessments required"
        );

        // If validators determined this is not human-created
        // or is a duplicate, score is set to zero and content
        // is marked inactive — removed from all pools
        if (!humanVerified) {
            registry[contentHash].active = false;
            registry[contentHash].verified = true;
            registry[contentHash].contributionScore = 0;

            emit ScoreUpdated(contentHash, 0, 0, block.timestamp);
            return;
        }

        uint256 oldScore = registry[contentHash].contributionScore;

        registry[contentHash].contributionScore = finalScore;
        registry[contentHash].verified = true;

        totalVerified++;

        emit ContentVerified(
            contentHash,
            registry[contentHash].creator,
            finalScore,
            block.timestamp
        );

        emit ScoreUpdated(contentHash, oldScore, finalScore, block.timestamp);
    }

    // ─────────────────────────────────────────────
    // VIEW FUNCTIONS
    // ─────────────────────────────────────────────

    /**
     * @notice Get the full record for a registered content piece
     */
    function getRecord(bytes32 contentHash)
        external
        view
        returns (ContentRecord memory)
    {
        return registry[contentHash];
    }

    /**
     * @notice Check if a content hash is registered and active
     */
    function isActiveContent(bytes32 contentHash)
        external
        view
        returns (bool)
    {
        return registry[contentHash].active &&
               registry[contentHash].creator != address(0);
    }

    /**
     * @notice Check if a creator is eligible for mining rewards.
     *         Wallet must have been first seen at least 7 days ago.
     *         Anti-sybil protection.
     */
    function isMiningEligible(address creator)
        external
        view
        returns (bool)
    {
        if (walletFirstSeen[creator] == 0) return false;
        uint256 daysActive = (block.timestamp - walletFirstSeen[creator]) / 1 days;
        return daysActive >= MIN_WALLET_AGE_DAYS;
    }

    /**
     * @notice Get all content hashes registered by a creator
     */
    function getCreatorRegistrations(address creator)
        external
        view
        returns (bytes32[] memory)
    {
        return creatorRegistrations[creator];
    }

    /**
     * @notice Get the number of registrations by a creator
     */
    function getCreatorRegistrationCount(address creator)
        external
        view
        returns (uint256)
    {
        return creatorRegistrations[creator].length;
    }

    /**
     * @notice Get all versions of a content piece
     * @param parentHash The original content hash
     */
    function getContentVersions(bytes32 parentHash)
        external
        view
        returns (bytes32[] memory)
    {
        return contentVersions[parentHash];
    }

    /**
     * @notice Get all validator assessments for a content piece
     */
    function getAssessments(bytes32 contentHash)
        external
        view
        returns (ValidatorAssessment[] memory)
    {
        return assessments[contentHash];
    }

    /**
     * @notice Get the number of validator assessments for a content piece
     */
    function getAssessmentCount(bytes32 contentHash)
        external
        view
        returns (uint256)
    {
        return assessments[contentHash].length;
    }

    // ─────────────────────────────────────────────
    // ADMIN FUNCTIONS
    // ─────────────────────────────────────────────

    /**
     * @notice Authorize or deauthorize a validator contract.
     *         Only the owner (later: governance) can call this.
     */
    function setValidator(address validator, bool authorized)
        external
        onlyOwner
    {
        require(validator != address(0), "DataProof: invalid validator address");
        authorizedValidators[validator] = authorized;
        emit ValidatorAuthorized(validator, authorized);
    }

    /**
     * @notice Set the OGN token contract address.
     *         Called once after both contracts are deployed.
     */
    function setOGNToken(address tokenContract) external onlyOwner {
        require(tokenContract != address(0), "DataProof: invalid token address");
        ognTokenContract = tokenContract;
    }

    /**
     * @notice Set the ValidatorPool contract address.
     */
    function setValidatorPool(address poolContract) external onlyOwner {
        require(poolContract != address(0), "DataProof: invalid pool address");
        validatorPoolContract = poolContract;
    }

    /**
     * @notice Activate a new content type — called by governance
     *         after a category is proven in production.
     *         In v1 only code (type 0) is active.
     */
    function activateContentType(uint8 contentType) external onlyOwner {
        require(contentType <= TYPE_DATASET, "DataProof: invalid content type");
        require(
            !activeContentTypes[contentType],
            "DataProof: content type already active"
        );
        activeContentTypes[contentType] = true;
        emit ContentTypeActivated(contentType, block.timestamp);
    }

    /**
     * @notice Emergency pause — freezes all registrations.
     *         Used only if a critical vulnerability is discovered.
     */
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
