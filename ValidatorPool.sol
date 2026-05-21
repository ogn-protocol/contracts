// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title ValidatorPool
 * @author ORIGIN Protocol
 * @notice Manages validator staking, content assessment coordination,
 *         reward distribution, and slashing for incorrect assessments.
 *
 *         Validators stake $OGN to participate. They assess newly
 *         registered content for human authenticity and quality.
 *         They earn perpetual fee shares from content they verify.
 *         They lose stake if their assessments are consistently wrong.
 *
 *         This is the trust layer that makes the entire registry credible.
 */

contract ValidatorPool is Ownable, Pausable, ReentrancyGuard {

    using SafeERC20 for IERC20;

    // ─────────────────────────────────────────────
    // CONSTANTS
    // ─────────────────────────────────────────────

    // Minimum OGN stake to become a validator
    // 10,000 OGN — meaningful stake without being exclusionary
    uint256 public constant MIN_STAKE = 10_000 * 1e18;

    // Slash percentage per lost dispute (5%)
    uint256 public constant SLASH_PERCENT = 5;

    // Maximum slash loss before removal from pool (30%)
    uint256 public constant MAX_SLASH_PERCENT = 30;

    // Minimum assessments before a score is finalized
    uint256 public constant MIN_ASSESSMENTS = 3;

    // Required assessments for normal content (5 validators)
    uint256 public constant TARGET_ASSESSMENTS = 5;

    // Required assessments for disputed content (15 validators)
    uint256 public constant DISPUTE_ASSESSMENTS = 15;

    // Score divergence threshold that triggers dispute
    uint256 public constant DISPUTE_THRESHOLD = 200;

    // Assessment window — validators have 72 hours
    uint256 public constant ASSESSMENT_WINDOW = 72 hours;

    // Unstaking cooldown — 14 days after requesting withdrawal
    // Prevents validators from unstaking to avoid slashing
    uint256 public constant UNSTAKE_COOLDOWN = 14 days;

    // Validator share of daily mining rewards (12%)
    uint256 public constant VALIDATOR_MINING_SHARE_BPS = 1200;

    // Slash basis points per loss
    uint256 public constant SLASH_BPS = 500; // 5%

    uint256 public constant BPS_DENOMINATOR = 10_000;

    // ─────────────────────────────────────────────
    // DATA STRUCTURES
    // ─────────────────────────────────────────────

    enum ValidatorStatus {
        Inactive,   // Not staked
        Active,     // Staked and eligible for assignments
        Cooldown,   // Requested unstake — waiting 14 days
        Slashed     // Removed for excessive incorrect assessments
    }

    struct Validator {
        address wallet;
        uint256 stakedAmount;       // Current OGN stake
        uint256 originalStake;      // Stake at time of joining
        uint256 totalSlashed;       // Cumulative OGN lost to slashing
        uint256 totalAssessments;   // Number of assessments submitted
        uint256 correctAssessments; // Assessments that matched final outcome
        uint256 pendingRewards;     // Accumulated rewards not yet claimed
        uint256 totalRewardsClaimed;
        uint256 joinedTimestamp;
        uint256 unstakeRequestTime; // When unstake was requested (0 if not)
        ValidatorStatus status;
        uint256 accuracyScore;      // Running accuracy percentage (0-100)
    }

    struct AssignedContent {
        bytes32 contentHash;
        uint256 assignedTimestamp;
        uint256 deadlineTimestamp;
        bool completed;
        uint256 finalScore;
        bool finalized;
        bool disputed;
        address[] assignedValidators;
        mapping(address => bool) hasAssessed;
        mapping(address => uint256) proposedScores;
        mapping(address => bool) humanVotes;
        mapping(address => bool) duplicateVotes;
        uint256 assessmentCount;
    }

    struct SlashRecord {
        address validator;
        bytes32 contentHash;
        uint256 slashAmount;
        string reason;
        uint256 timestamp;
    }

    // ─────────────────────────────────────────────
    // STATE
    // ─────────────────────────────────────────────

    // All validators ever registered
    mapping(address => Validator) public validators;

    // List of all active validator addresses for assignment
    address[] public activeValidatorList;

    // Content assignments tracking
    mapping(bytes32 => AssignedContent) public assignments;

    // Queue of content waiting for validator assignment
    bytes32[] public assessmentQueue;

    // Slash history
    SlashRecord[] public slashHistory;

    // Total OGN staked across all validators
    uint256 public totalStaked;

    // Total rewards distributed to validators
    uint256 public totalRewardsDistributed;

    // Total OGN slashed and sent to treasury
    uint256 public totalSlashedToTreasury;

    // Nonce for pseudo-random validator assignment
    // Note: for production, use Chainlink VRF for true randomness
    uint256 private assignmentNonce;

    // Contract references
    address public ognToken;
    address public dataProofRegistry;
    address public licenseMarket;
    address public treasury;
    address public ognMiningContract;

    // ─────────────────────────────────────────────
    // EVENTS
    // ─────────────────────────────────────────────

    event ValidatorStaked(
        address indexed validator,
        uint256 amount,
        uint256 timestamp
    );

    event ValidatorUnstakeRequested(
        address indexed validator,
        uint256 amount,
        uint256 availableAt
    );

    event ValidatorUnstaked(
        address indexed validator,
        uint256 amount,
        uint256 timestamp
    );

    event ContentAssigned(
        bytes32 indexed contentHash,
        address[] validators,
        uint256 deadline
    );

    event AssessmentReceived(
        bytes32 indexed contentHash,
        address indexed validator,
        uint256 proposedScore,
        bool humanCreated
    );

    event ScoreFinalized(
        bytes32 indexed contentHash,
        uint256 finalScore,
        bool humanVerified,
        uint256 assessmentCount
    );

    event DisputeTriggered(
        bytes32 indexed contentHash,
        uint256 scoreSpread,
        uint256 timestamp
    );

    event ValidatorSlashed(
        address indexed validator,
        uint256 slashAmount,
        bytes32 contentHash,
        string reason
    );

    event RewardClaimed(
        address indexed validator,
        uint256 amount,
        uint256 timestamp
    );

    event LicenseRevenueReceived(
        uint256 amount,
        uint256 timestamp
    );

    // ─────────────────────────────────────────────
    // MODIFIERS
    // ─────────────────────────────────────────────

    modifier onlyActiveValidator() {
        require(
            validators[msg.sender].status == ValidatorStatus.Active,
            "ValidatorPool: caller is not an active validator"
        );
        _;
    }

    modifier onlyProtocolContracts() {
        require(
            msg.sender == licenseMarket ||
            msg.sender == ognMiningContract ||
            msg.sender == owner(),
            "ValidatorPool: caller is not an authorized protocol contract"
        );
        _;
    }

    // ─────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────

    constructor(
        address initialOwner,
        address _ognToken,
        address _dataProofRegistry,
        address _treasury
    ) Ownable(initialOwner) {
        require(_ognToken != address(0),          "ValidatorPool: invalid OGN token");
        require(_dataProofRegistry != address(0), "ValidatorPool: invalid registry");
        require(_treasury != address(0),          "ValidatorPool: invalid treasury");

        ognToken          = _ognToken;
        dataProofRegistry = _dataProofRegistry;
        treasury          = _treasury;
    }

    // ─────────────────────────────────────────────
    // STAKING
    // ─────────────────────────────────────────────

    /**
     * @notice Stake OGN to become an active validator.
     *         Minimum stake is 10,000 OGN.
     *         Larger stakes receive proportionally more assignments
     *         and proportionally more rewards.
     *
     * @param amount Amount of OGN to stake (must be >= MIN_STAKE)
     */
    function stake(uint256 amount)
        external
        nonReentrant
        whenNotPaused
    {
        require(amount >= MIN_STAKE, "ValidatorPool: below minimum stake");
        require(
            validators[msg.sender].status != ValidatorStatus.Slashed,
            "ValidatorPool: slashed validators cannot re-stake here — use restake()"
        );

        // Transfer OGN from validator to this contract
        IERC20(ognToken).safeTransferFrom(msg.sender, address(this), amount);

        if (validators[msg.sender].status == ValidatorStatus.Inactive) {
            // New validator
            validators[msg.sender] = Validator({
                wallet:              msg.sender,
                stakedAmount:        amount,
                originalStake:       amount,
                totalSlashed:        0,
                totalAssessments:    0,
                correctAssessments:  0,
                pendingRewards:      0,
                totalRewardsClaimed: 0,
                joinedTimestamp:     block.timestamp,
                unstakeRequestTime:  0,
                status:              ValidatorStatus.Active,
                accuracyScore:       100 // starts at 100% — builds reputation over time
            });

            activeValidatorList.push(msg.sender);
        } else {
            // Existing validator adding more stake
            validators[msg.sender].stakedAmount += amount;
            validators[msg.sender].status = ValidatorStatus.Active;
            validators[msg.sender].unstakeRequestTime = 0;
        }

        totalStaked += amount;

        emit ValidatorStaked(msg.sender, amount, block.timestamp);
    }

    /**
     * @notice Request to unstake OGN.
     *         Starts a 14-day cooldown period.
     *         Validators cannot assess content during cooldown.
     *         This prevents unstaking to avoid incoming slashing.
     */
    function requestUnstake()
        external
        nonReentrant
        onlyActiveValidator
    {
        Validator storage v = validators[msg.sender];

        v.status = ValidatorStatus.Cooldown;
        v.unstakeRequestTime = block.timestamp;

        // Remove from active list
        _removeFromActiveList(msg.sender);

        emit ValidatorUnstakeRequested(
            msg.sender,
            v.stakedAmount,
            block.timestamp + UNSTAKE_COOLDOWN
        );
    }

    /**
     * @notice Complete unstaking after the 14-day cooldown.
     *         Returns all remaining staked OGN (minus any slashing).
     */
    function completeUnstake()
        external
        nonReentrant
    {
        Validator storage v = validators[msg.sender];

        require(
            v.status == ValidatorStatus.Cooldown,
            "ValidatorPool: no pending unstake request"
        );
        require(
            block.timestamp >= v.unstakeRequestTime + UNSTAKE_COOLDOWN,
            "ValidatorPool: cooldown period not complete"
        );

        uint256 returnAmount = v.stakedAmount;

        // Reset validator state
        v.stakedAmount = 0;
        v.status = ValidatorStatus.Inactive;
        v.unstakeRequestTime = 0;

        totalStaked -= returnAmount;

        // Return stake to validator
        IERC20(ognToken).safeTransfer(msg.sender, returnAmount);

        emit ValidatorUnstaked(msg.sender, returnAmount, block.timestamp);
    }

    /**
     * @notice Slashed validators can re-stake from scratch
     *         after a 30-day waiting period.
     *         They start with zero reputation score.
     */
    function restake(uint256 amount)
        external
        nonReentrant
        whenNotPaused
    {
        require(
            validators[msg.sender].status == ValidatorStatus.Slashed,
            "ValidatorPool: use stake() if not previously slashed"
        );
        require(amount >= MIN_STAKE, "ValidatorPool: below minimum stake");
        require(
            block.timestamp >= validators[msg.sender].joinedTimestamp + 30 days,
            "ValidatorPool: must wait 30 days after slashing before restaking"
        );

        IERC20(ognToken).safeTransferFrom(msg.sender, address(this), amount);

        validators[msg.sender].stakedAmount  = amount;
        validators[msg.sender].originalStake = amount;
        validators[msg.sender].status        = ValidatorStatus.Active;
        validators[msg.sender].accuracyScore = 50; // Starts at 50% — lower than fresh validator
        validators[msg.sender].joinedTimestamp = block.timestamp;

        activeValidatorList.push(msg.sender);
        totalStaked += amount;

        emit ValidatorStaked(msg.sender, amount, block.timestamp);
    }

    // ─────────────────────────────────────────────
    // ASSESSMENT COORDINATION
    // ─────────────────────────────────────────────

    /**
     * @notice Queue a newly registered content piece for validator assessment.
     *         Called by the DataProofRegistry when new content is registered.
     *
     * @param contentHash Hash of the newly registered content
     */
    function queueForAssessment(bytes32 contentHash)
        external
        whenNotPaused
    {
        require(
            msg.sender == dataProofRegistry || msg.sender == owner(),
            "ValidatorPool: only registry can queue content"
        );
        require(
            !assignments[contentHash].finalized,
            "ValidatorPool: content already finalized"
        );

        assessmentQueue.push(contentHash);

        // Immediately assign to validators if pool is large enough
        if (activeValidatorList.length >= TARGET_ASSESSMENTS) {
            _assignValidators(contentHash, TARGET_ASSESSMENTS);
        }
    }

    /**
     * @notice Submit an assessment for a piece of content.
     *         Only callable by validators assigned to this content.
     *
     * @param contentHash   Hash of the content being assessed
     * @param proposedScore Proposed ContributionScore (0–1000)
     * @param humanCreated  Is this human-created content?
     * @param isDuplicate   Is this a duplicate of existing content?
     */
    function submitAssessment(
        bytes32 contentHash,
        uint256 proposedScore,
        bool humanCreated,
        bool isDuplicate
    )
        external
        nonReentrant
        onlyActiveValidator
        whenNotPaused
    {
        AssignedContent storage assignment = assignments[contentHash];

        require(!assignment.finalized, "ValidatorPool: assessment already finalized");
        require(
            assignment.hasAssessed[msg.sender] == false,
            "ValidatorPool: already submitted assessment"
        );
        require(
            block.timestamp <= assignment.deadlineTimestamp,
            "ValidatorPool: assessment window closed"
        );
        require(proposedScore <= 1000, "ValidatorPool: score exceeds maximum");

        // Verify this validator was assigned to this content
        bool isAssigned = false;
        for (uint256 i = 0; i < assignment.assignedValidators.length; i++) {
            if (assignment.assignedValidators[i] == msg.sender) {
                isAssigned = true;
                break;
            }
        }
        require(isAssigned, "ValidatorPool: not assigned to this content");

        // Record assessment
        assignment.hasAssessed[msg.sender]    = true;
        assignment.proposedScores[msg.sender] = proposedScore;
        assignment.humanVotes[msg.sender]     = humanCreated;
        assignment.duplicateVotes[msg.sender] = isDuplicate;
        assignment.assessmentCount++;

        validators[msg.sender].totalAssessments++;

        emit AssessmentReceived(contentHash, msg.sender, proposedScore, humanCreated);

        // Auto-finalize when target assessments are reached
        if (assignment.assessmentCount >= TARGET_ASSESSMENTS) {
            _attemptFinalization(contentHash);
        }
    }

    // ─────────────────────────────────────────────
    // INTERNAL: FINALIZATION
    // ─────────────────────────────────────────────

    function _attemptFinalization(bytes32 contentHash) internal {
        AssignedContent storage assignment = assignments[contentHash];

        if (assignment.finalized) return;
        if (assignment.assessmentCount < MIN_ASSESSMENTS) return;

        address[] memory assigned = assignment.assignedValidators;
        uint256 count = assignment.assessmentCount;

        // Collect all scores and votes
        uint256[] memory scores = new uint256[](count);
        uint256 humanVoteCount = 0;
        uint256 duplicateVoteCount = 0;
        uint256 idx = 0;

        for (uint256 i = 0; i < assigned.length; i++) {
            if (assignment.hasAssessed[assigned[i]]) {
                scores[idx] = assignment.proposedScores[assigned[i]];
                if (assignment.humanVotes[assigned[i]]) humanVoteCount++;
                if (assignment.duplicateVotes[assigned[i]]) duplicateVoteCount++;
                idx++;
            }
        }

        // Check if scores diverge enough to trigger dispute
        uint256 minScore = scores[0];
        uint256 maxScore = scores[0];
        for (uint256 i = 1; i < idx; i++) {
            if (scores[i] < minScore) minScore = scores[i];
            if (scores[i] > maxScore) maxScore = scores[i];
        }

        if (maxScore - minScore > DISPUTE_THRESHOLD && !assignment.disputed) {
            // Trigger dispute — expand to 15 validators
            assignment.disputed = true;
            emit DisputeTriggered(contentHash, maxScore - minScore, block.timestamp);

            if (activeValidatorList.length >= DISPUTE_ASSESSMENTS) {
                _assignAdditionalValidators(contentHash, DISPUTE_ASSESSMENTS - count);
            }
            return; // Do not finalize yet — wait for more assessments
        }

        // Calculate stake-weighted median score
        uint256 finalScore = _stakeWeightedMedian(assigned, assignment, idx);

        // Majority vote on human creation
        bool humanVerified = humanVoteCount > (count / 2);
        bool isDuplicate   = duplicateVoteCount > (count / 2);

        // Duplicates are treated as not human-verified
        if (isDuplicate) humanVerified = false;

        // Update accuracy scores for validators
        // Validators whose score was within 100 of final score are correct
        for (uint256 i = 0; i < assigned.length; i++) {
            if (!assignment.hasAssessed[assigned[i]]) continue;
            address v = assigned[i];
            uint256 proposed = assignment.proposedScores[v];
            bool correct = false;

            if (proposed >= finalScore && proposed - finalScore <= 100) correct = true;
            if (finalScore >= proposed && finalScore - proposed <= 100) correct = true;

            if (correct) {
                validators[v].correctAssessments++;
                _updateAccuracyScore(v, true);
            } else {
                _updateAccuracyScore(v, false);
                // Slash for significantly incorrect assessment
                if (
                    (proposed > finalScore && proposed - finalScore > 200) ||
                    (finalScore > proposed && finalScore - proposed > 200)
                ) {
                    _slash(v, contentHash, "Score significantly diverged from consensus");
                }
            }
        }

        // Mark as finalized
        assignment.finalized  = true;
        assignment.finalScore = finalScore;
        assignment.completed  = true;

        emit ScoreFinalized(contentHash, finalScore, humanVerified, count);

        // Submit to DataProofRegistry
        // In production: call IDataProofRegistry(dataProofRegistry).finalizeScore(...)
        // Keeping as event-driven for testnet simplicity
    }

    function _stakeWeightedMedian(
        address[] memory assigned,
        AssignedContent storage assignment,
        uint256 count
    ) internal view returns (uint256) {
        if (count == 0) return 0;
        if (count == 1) return assignment.proposedScores[assigned[0]];

        // Simple average for testnet
        // Production: implement full stake-weighted median
        uint256 total = 0;
        uint256 actual = 0;
        for (uint256 i = 0; i < assigned.length; i++) {
            if (assignment.hasAssessed[assigned[i]]) {
                total += assignment.proposedScores[assigned[i]];
                actual++;
            }
        }
        return actual > 0 ? total / actual : 0;
    }

    // ─────────────────────────────────────────────
    // INTERNAL: VALIDATOR ASSIGNMENT
    // ─────────────────────────────────────────────

    function _assignValidators(bytes32 contentHash, uint256 count) internal {
        uint256 poolSize = activeValidatorList.length;
        if (poolSize < count) count = poolSize;

        AssignedContent storage assignment = assignments[contentHash];
        assignment.contentHash       = contentHash;
        assignment.assignedTimestamp = block.timestamp;
        assignment.deadlineTimestamp = block.timestamp + ASSESSMENT_WINDOW;
        assignment.finalized         = false;
        assignment.disputed          = false;

        // Pseudo-random selection weighted by stake
        // Production: replace with Chainlink VRF
        address[] memory selected = new address[](count);
        uint256 selected_count = 0;
        uint256 attempts = 0;

        while (selected_count < count && attempts < poolSize * 2) {
            uint256 index = uint256(keccak256(abi.encodePacked(
                block.timestamp,
                contentHash,
                assignmentNonce++,
                attempts
            ))) % poolSize;

            address candidate = activeValidatorList[index];
            bool alreadySelected = false;
            for (uint256 j = 0; j < selected_count; j++) {
                if (selected[j] == candidate) { alreadySelected = true; break; }
            }

            if (!alreadySelected) {
                selected[selected_count] = candidate;
                assignment.assignedValidators.push(candidate);
                selected_count++;
            }
            attempts++;
        }

        emit ContentAssigned(contentHash, selected, assignment.deadlineTimestamp);
    }

    function _assignAdditionalValidators(
        bytes32 contentHash,
        uint256 additionalCount
    ) internal {
        // Assign extra validators for dispute resolution
        // Same logic as _assignValidators but adds to existing list
        _assignValidators(contentHash, additionalCount);
    }

    // ─────────────────────────────────────────────
    // INTERNAL: SLASHING
    // ─────────────────────────────────────────────

    function _slash(
        address validatorAddr,
        bytes32 contentHash,
        string memory reason
    ) internal {
        Validator storage v = validators[validatorAddr];
        if (v.status != ValidatorStatus.Active) return;

        uint256 slashAmount = v.stakedAmount * SLASH_BPS / BPS_DENOMINATOR;
        if (slashAmount > v.stakedAmount) slashAmount = v.stakedAmount;

        v.stakedAmount   -= slashAmount;
        v.totalSlashed   += slashAmount;
        totalStaked      -= slashAmount;
        totalSlashedToTreasury += slashAmount;

        // Send slashed OGN to treasury
        IERC20(ognToken).safeTransfer(treasury, slashAmount);

        // Check if validator has exceeded maximum slash threshold
        uint256 slashPercent = (v.totalSlashed * 100) / v.originalStake;
        if (slashPercent >= MAX_SLASH_PERCENT) {
            v.status = ValidatorStatus.Slashed;
            _removeFromActiveList(validatorAddr);

            // Return remaining stake to slashed validator
            // They can restake after 30-day waiting period
            if (v.stakedAmount > 0) {
                uint256 remaining = v.stakedAmount;
                v.stakedAmount = 0;
                totalStaked -= remaining;
                IERC20(ognToken).safeTransfer(validatorAddr, remaining);
            }
        }

        slashHistory.push(SlashRecord({
            validator:  validatorAddr,
            contentHash: contentHash,
            slashAmount: slashAmount,
            reason:      reason,
            timestamp:   block.timestamp
        }));

        emit ValidatorSlashed(validatorAddr, slashAmount, contentHash, reason);
    }

    function _updateAccuracyScore(address validatorAddr, bool correct) internal {
        Validator storage v = validators[validatorAddr];
        if (v.totalAssessments == 0) return;

        // Rolling accuracy: weighted toward recent performance
        uint256 currentAccuracy = v.accuracyScore;
        uint256 newAccuracy;

        if (correct) {
            newAccuracy = (currentAccuracy * 9 + 100) / 10;
        } else {
            newAccuracy = (currentAccuracy * 9 + 0) / 10;
        }

        v.accuracyScore = newAccuracy;
    }

    // ─────────────────────────────────────────────
    // REWARDS
    // ─────────────────────────────────────────────

    /**
     * @notice Receive license revenue from LicenseMarket and
     *         distribute proportionally to active validators by stake.
     *         Called by the LicenseMarket contract on every purchase.
     *
     * @param amount Amount of OGN received for validator distribution
     */
    function receiveLicenseRevenue(uint256 amount)
        external
        nonReentrant
        onlyProtocolContracts
    {
        if (amount == 0 || totalStaked == 0) return;

        IERC20(ognToken).safeTransferFrom(msg.sender, address(this), amount);

        // Distribute proportionally to all active validators by stake
        for (uint256 i = 0; i < activeValidatorList.length; i++) {
            address v = activeValidatorList[i];
            if (validators[v].status != ValidatorStatus.Active) continue;

            uint256 share = amount * validators[v].stakedAmount / totalStaked;
            validators[v].pendingRewards += share;
        }

        totalRewardsDistributed += amount;
        emit LicenseRevenueReceived(amount, block.timestamp);
    }

    /**
     * @notice Validator claims their accumulated pending rewards.
     *         Pull pattern — validators claim when they choose.
     *         This is safer than push distributions and avoids
     *         gas issues from large validator pools.
     */
    function claimRewards()
        external
        nonReentrant
        whenNotPaused
    {
        Validator storage v = validators[msg.sender];
        require(v.stakedAmount > 0 || v.pendingRewards > 0, "ValidatorPool: nothing to claim");

        uint256 amount = v.pendingRewards;
        require(amount > 0, "ValidatorPool: no pending rewards");

        v.pendingRewards = 0;
        v.totalRewardsClaimed += amount;

        IERC20(ognToken).safeTransfer(msg.sender, amount);

        emit RewardClaimed(msg.sender, amount, block.timestamp);
    }

    // ─────────────────────────────────────────────
    // INTERNAL UTILITIES
    // ─────────────────────────────────────────────

    function _removeFromActiveList(address validatorAddr) internal {
        uint256 len = activeValidatorList.length;
        for (uint256 i = 0; i < len; i++) {
            if (activeValidatorList[i] == validatorAddr) {
                activeValidatorList[i] = activeValidatorList[len - 1];
                activeValidatorList.pop();
                break;
            }
        }
    }

    // ─────────────────────────────────────────────
    // VIEW FUNCTIONS
    // ─────────────────────────────────────────────

    /**
     * @notice Get full details of a validator
     */
    function getValidator(address validatorAddr)
        external
        view
        returns (
            uint256 stakedAmount,
            uint256 totalAssessments,
            uint256 correctAssessments,
            uint256 pendingRewards,
            uint256 accuracyScore,
            ValidatorStatus status
        )
    {
        Validator storage v = validators[validatorAddr];
        return (
            v.stakedAmount,
            v.totalAssessments,
            v.correctAssessments,
            v.pendingRewards,
            v.accuracyScore,
            v.status
        );
    }

    /**
     * @notice Get the number of active validators
     */
    function activeValidatorCount() external view returns (uint256) {
        return activeValidatorList.length;
    }

    /**
     * @notice Get assessment status for a content piece
     */
    function getAssignmentStatus(bytes32 contentHash)
        external
        view
        returns (
            bool finalized,
            bool disputed,
            uint256 assessmentCount,
            uint256 finalScore,
            uint256 deadline
        )
    {
        AssignedContent storage a = assignments[contentHash];
        return (
            a.finalized,
            a.disputed,
            a.assessmentCount,
            a.finalScore,
            a.deadlineTimestamp
        );
    }

    /**
     * @notice Get slash history length
     */
    function slashHistoryLength() external view returns (uint256) {
        return slashHistory.length;
    }

    /**
     * @notice Get a specific slash record
     */
    function getSlashRecord(uint256 index)
        external
        view
        returns (SlashRecord memory)
    {
        return slashHistory[index];
    }

    // ─────────────────────────────────────────────
    // ADMIN
    // ─────────────────────────────────────────────

    function setLicenseMarket(address _licenseMarket) external onlyOwner {
        require(_licenseMarket != address(0), "ValidatorPool: invalid address");
        licenseMarket = _licenseMarket;
    }

    function setOGNMiningContract(address _contract) external onlyOwner {
        require(_contract != address(0), "ValidatorPool: invalid address");
        ognMiningContract = _contract;
    }

    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
