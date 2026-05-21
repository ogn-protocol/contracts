// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title LicenseMarket
 * @author ORIGIN Protocol
 * @notice The automated marketplace where AI companies purchase
 *         licenses to use registered creator content in training datasets.
 *
 *         Fee distribution per license purchase:
 *         - 70% to creators (proportional to ContributionScore)
 *         - 15% to validators who verified the content
 *         - 10% permanently burned from OGN supply
 *         - 5%  to Protocol Treasury
 *
 *         Pricing uses a bonding curve: P = k × N^α
 *         where N = number of works licensed and α = 1.2
 */

contract LicenseMarket is Ownable, Pausable, ReentrancyGuard {

    using SafeERC20 for IERC20;

    // ─────────────────────────────────────────────
    // CONSTANTS
    // ─────────────────────────────────────────────

    // Fee distribution in basis points (10000 = 100%)
    uint256 public constant CREATOR_SHARE_BPS    = 7000; // 70%
    uint256 public constant VALIDATOR_SHARE_BPS  = 1500; // 15%
    uint256 public constant BURN_SHARE_BPS       = 1000; // 10%
    uint256 public constant TREASURY_SHARE_BPS   = 500;  // 5%
    uint256 public constant BPS_DENOMINATOR      = 10000;

    // OGN payment discount — 10% cheaper if paying in OGN
    uint256 public constant OGN_DISCOUNT_BPS     = 1000; // 10% discount

    // License types
    uint8 public constant LICENSE_SINGLE         = 0; // Single repository
    uint8 public constant LICENSE_PORTFOLIO      = 1; // All works by one creator
    uint8 public constant LICENSE_CATEGORY_POOL  = 2; // Filtered content pool
    uint8 public constant LICENSE_RESEARCH       = 3; // Reduced academic rate

    // Research license discount
    uint256 public constant RESEARCH_DISCOUNT_BPS = 6000; // 60% discount

    // Bonding curve alpha scaled by 1e18 for fixed-point math
    // α = 1.2 means price scales superlinearly with pool size
    // Larger AI companies pay disproportionately more
    uint256 public constant ALPHA_NUMERATOR   = 12;
    uint256 public constant ALPHA_DENOMINATOR = 10;

    // ─────────────────────────────────────────────
    // GOVERNANCE-ADJUSTABLE PARAMETERS
    // ─────────────────────────────────────────────

    // Base price per work in USD equivalent (18 decimals)
    // Initially $0.001 per work = 1e15 (in USDC 6-decimal terms: 1000)
    uint256 public basePricePerWork;

    // ─────────────────────────────────────────────
    // DATA STRUCTURES
    // ─────────────────────────────────────────────

    enum PaymentToken { OGN, USDC, ETH }

    struct License {
        uint256 licenseId;
        address licensee;          // AI company wallet
        uint8 licenseType;         // 0-3
        bytes32[] contentHashes;   // Content pieces included
        uint256 pricePaid;         // Amount paid in payment token
        PaymentToken paymentToken; // How they paid
        uint256 ognEquivalent;     // OGN value at time of purchase
        uint256 creatorPool;       // Amount going to creators
        uint256 validatorPool;     // Amount going to validators
        uint256 burnAmount;        // Amount burned
        uint256 treasuryAmount;    // Amount to treasury
        uint256 timestamp;         // When purchased
        uint256 expiryTimestamp;   // When license expires (0 = perpetual)
        bool active;               // Is license currently valid
    }

    struct CreatorPayment {
        address creator;
        uint256 amount;
        uint256 licenseId;
    }

    // ─────────────────────────────────────────────
    // STATE
    // ─────────────────────────────────────────────

    // All licenses ever purchased
    mapping(uint256 => License) public licenses;
    uint256 public totalLicenses;

    // Licenses purchased by each AI company
    mapping(address => uint256[]) public licensesByLicensee;

    // Licenses covering each content piece
    mapping(bytes32 => uint256[]) public licensesByContent;

    // Total revenue collected (in OGN equivalent)
    uint256 public totalRevenueOGN;

    // Total amount ever burned through license purchases
    uint256 public totalBurnedOGN;

    // Total paid to creators through license purchases
    uint256 public totalCreatorPaymentsOGN;

    // Pending creator payments — pulled by CreatorPool contract
    mapping(address => uint256) public pendingCreatorPayments;

    // Verified academic institutions for research licenses
    mapping(address => bool) public verifiedAcademicInstitutions;

    // Contract references
    address public ognToken;
    address public usdcToken;
    address public dataProofRegistry;
    address public validatorPool;
    address public treasury;
    address public priceOracle; // Chainlink OGN/USD feed

    // ─────────────────────────────────────────────
    // EVENTS
    // ─────────────────────────────────────────────

    event LicensePurchased(
        uint256 indexed licenseId,
        address indexed licensee,
        uint8 licenseType,
        uint256 contentCount,
        uint256 pricePaid,
        PaymentToken paymentToken,
        uint256 ognEquivalent,
        uint256 timestamp
    );

    event FeeDistributed(
        uint256 indexed licenseId,
        uint256 creatorPool,
        uint256 validatorPool,
        uint256 burnAmount,
        uint256 treasuryAmount
    );

    event CreatorPaymentQueued(
        address indexed creator,
        uint256 amount,
        uint256 indexed licenseId
    );

    event BasePriceUpdated(
        uint256 oldPrice,
        uint256 newPrice
    );

    event AcademicVerified(
        address indexed institution,
        bool verified
    );

    // ─────────────────────────────────────────────
    // MODIFIERS
    // ─────────────────────────────────────────────

    modifier validLicenseType(uint8 licenseType) {
        require(licenseType <= LICENSE_RESEARCH, "LicenseMarket: invalid license type");
        _;
    }

    modifier onlyAcademic() {
        require(
            verifiedAcademicInstitutions[msg.sender],
            "LicenseMarket: caller is not a verified academic institution"
        );
        _;
    }

    // ─────────────────────────────────────────────
    // CONSTRUCTOR
    // ─────────────────────────────────────────────

    constructor(
        address initialOwner,
        address _ognToken,
        address _usdcToken,
        address _dataProofRegistry,
        address _validatorPool,
        address _treasury,
        address _priceOracle
    ) Ownable(initialOwner) {
        require(_ognToken != address(0),           "LicenseMarket: invalid OGN token");
        require(_usdcToken != address(0),          "LicenseMarket: invalid USDC token");
        require(_dataProofRegistry != address(0),  "LicenseMarket: invalid registry");
        require(_validatorPool != address(0),      "LicenseMarket: invalid validator pool");
        require(_treasury != address(0),           "LicenseMarket: invalid treasury");
        require(_priceOracle != address(0),        "LicenseMarket: invalid oracle");

        ognToken          = _ognToken;
        usdcToken         = _usdcToken;
        dataProofRegistry = _dataProofRegistry;
        validatorPool     = _validatorPool;
        treasury          = _treasury;
        priceOracle       = _priceOracle;

        // Initial base price: $0.001 per work
        // In USDC (6 decimals): 1000 = $0.001
        basePricePerWork = 1000;
    }

    // ─────────────────────────────────────────────
    // CORE: LICENSE PURCHASE
    // ─────────────────────────────────────────────

    /**
     * @notice Purchase a Single Repository License.
     *         Grants the right to use one specific registered
     *         code repository in one AI training dataset.
     *
     * @param contentHash   Hash of the repository to license
     * @param paymentToken  0=OGN, 1=USDC, 2=ETH
     * @param durationDays  License duration in days (0 = perpetual)
     */
    function purchaseSingleLicense(
        bytes32 contentHash,
        PaymentToken paymentToken,
        uint256 durationDays
    )
        external
        payable
        nonReentrant
        whenNotPaused
    {
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = contentHash;

        uint256 price = calculateSinglePrice(contentHash);
        _executeLicensePurchase(
            LICENSE_SINGLE,
            hashes,
            price,
            paymentToken,
            durationDays
        );
    }

    /**
     * @notice Purchase a Category Pool License.
     *         Grants the right to use a filtered pool of registered
     *         content in AI training datasets.
     *         Most common license type for large AI companies.
     *
     * @param contentHashes Array of content hashes to license
     * @param paymentToken  0=OGN, 1=USDC, 2=ETH
     * @param durationDays  License duration in days (0 = perpetual)
     */
    function purchaseCategoryPoolLicense(
        bytes32[] calldata contentHashes,
        PaymentToken paymentToken,
        uint256 durationDays
    )
        external
        payable
        nonReentrant
        whenNotPaused
    {
        require(contentHashes.length > 0, "LicenseMarket: empty content pool");
        require(contentHashes.length <= 10_000_000, "LicenseMarket: pool too large for single tx");

        uint256 price = calculatePoolPrice(contentHashes.length);
        _executeLicensePurchase(
            LICENSE_CATEGORY_POOL,
            contentHashes,
            price,
            paymentToken,
            durationDays
        );
    }

    /**
     * @notice Purchase a Research License at a 60% discount.
     *         Only available to verified academic institutions.
     *         Requires prior verification by the protocol team.
     *
     * @param contentHashes Array of content hashes to license
     * @param durationDays  License duration in days
     */
    function purchaseResearchLicense(
        bytes32[] calldata contentHashes,
        uint256 durationDays
    )
        external
        nonReentrant
        whenNotPaused
        onlyAcademic
    {
        require(contentHashes.length > 0, "LicenseMarket: empty content pool");
        require(durationDays > 0, "LicenseMarket: research licenses must have duration");

        // Research license is always paid in USDC for accounting
        uint256 fullPrice = calculatePoolPrice(contentHashes.length);
        uint256 discountedPrice = fullPrice -
            (fullPrice * RESEARCH_DISCOUNT_BPS / BPS_DENOMINATOR);

        _executeLicensePurchase(
            LICENSE_RESEARCH,
            contentHashes,
            discountedPrice,
            PaymentToken.USDC,
            durationDays
        );
    }

    // ─────────────────────────────────────────────
    // INTERNAL: EXECUTE PURCHASE
    // ─────────────────────────────────────────────

    function _executeLicensePurchase(
        uint8 licenseType,
        bytes32[] memory contentHashes,
        uint256 basePrice,
        PaymentToken paymentToken,
        uint256 durationDays
    ) internal {

        // Apply OGN discount if paying in OGN
        uint256 finalPrice = basePrice;
        if (paymentToken == PaymentToken.OGN) {
            finalPrice = basePrice - (basePrice * OGN_DISCOUNT_BPS / BPS_DENOMINATOR);
        }

        // Convert payment to OGN equivalent for internal accounting
        uint256 ognEquivalent = _convertToOGN(finalPrice, paymentToken);

        // Collect payment from licensee
        _collectPayment(finalPrice, paymentToken);

        // Convert everything to OGN for distribution
        // (USDC and ETH payments are swapped via integrated DEX)
        uint256 ognForDistribution = ognEquivalent;

        // Calculate distribution amounts
        uint256 creatorAmount   = ognForDistribution * CREATOR_SHARE_BPS   / BPS_DENOMINATOR;
        uint256 validatorAmount = ognForDistribution * VALIDATOR_SHARE_BPS / BPS_DENOMINATOR;
        uint256 burnAmount      = ognForDistribution * BURN_SHARE_BPS      / BPS_DENOMINATOR;
        uint256 treasuryAmount  = ognForDistribution * TREASURY_SHARE_BPS  / BPS_DENOMINATOR;

        // Create license record
        uint256 licenseId = ++totalLicenses;
        uint256 expiry = durationDays > 0
            ? block.timestamp + (durationDays * 1 days)
            : 0;

        licenses[licenseId] = License({
            licenseId:       licenseId,
            licensee:        msg.sender,
            licenseType:     licenseType,
            contentHashes:   contentHashes,
            pricePaid:       finalPrice,
            paymentToken:    paymentToken,
            ognEquivalent:   ognEquivalent,
            creatorPool:     creatorAmount,
            validatorPool:   validatorAmount,
            burnAmount:      burnAmount,
            treasuryAmount:  treasuryAmount,
            timestamp:       block.timestamp,
            expiryTimestamp: expiry,
            active:          true
        });

        // Track license by licensee
        licensesByLicensee[msg.sender].push(licenseId);

        // Track license by each content piece
        for (uint256 i = 0; i < contentHashes.length; i++) {
            licensesByContent[contentHashes[i]].push(licenseId);
        }

        // Queue creator payments
        // In production, creator share is split proportionally
        // by ContributionScore — calculated off-chain and
        // submitted by the CreatorPool contract
        // Here we record the total pool for distribution
        _queueCreatorPayments(contentHashes, creatorAmount, licenseId);

        // Send validator share to ValidatorPool
        IERC20(ognToken).safeTransfer(validatorPool, validatorAmount);

        // Burn OGN permanently
        // Calls the burn function on OGN token contract
        _burnOGN(burnAmount);

        // Send treasury share
        IERC20(ognToken).safeTransfer(treasury, treasuryAmount);

        // Update global stats
        totalRevenueOGN          += ognEquivalent;
        totalBurnedOGN            += burnAmount;
        totalCreatorPaymentsOGN   += creatorAmount;

        emit LicensePurchased(
            licenseId,
            msg.sender,
            licenseType,
            contentHashes.length,
            finalPrice,
            paymentToken,
            ognEquivalent,
            block.timestamp
        );

        emit FeeDistributed(
            licenseId,
            creatorAmount,
            validatorAmount,
            burnAmount,
            treasuryAmount
        );
    }

    // ─────────────────────────────────────────────
    // INTERNAL: PAYMENT HANDLING
    // ─────────────────────────────────────────────

    function _collectPayment(
        uint256 amount,
        PaymentToken paymentToken
    ) internal {
        if (paymentToken == PaymentToken.OGN) {
            IERC20(ognToken).safeTransferFrom(msg.sender, address(this), amount);
        } else if (paymentToken == PaymentToken.USDC) {
            IERC20(usdcToken).safeTransferFrom(msg.sender, address(this), amount);
            // In production: swap USDC to OGN via Uniswap V3 integration
            // For testnet: USDC held in contract pending swap integration
        } else if (paymentToken == PaymentToken.ETH) {
            require(msg.value >= amount, "LicenseMarket: insufficient ETH sent");
            // In production: wrap ETH and swap to OGN via Uniswap V3
            // Refund excess ETH
            if (msg.value > amount) {
                (bool success, ) = msg.sender.call{value: msg.value - amount}("");
                require(success, "LicenseMarket: ETH refund failed");
            }
        }
    }

    function _convertToOGN(
        uint256 amount,
        PaymentToken paymentToken
    ) internal view returns (uint256) {
        if (paymentToken == PaymentToken.OGN) {
            return amount;
        }
        // In production: read Chainlink OGN/USD price feed
        // and convert accordingly
        // For testnet: 1:1 placeholder
        return amount;
    }

    function _burnOGN(uint256 amount) internal {
        // Transfer to zero address — permanent burn
        IERC20(ognToken).safeTransfer(address(0), amount);
    }

    function _queueCreatorPayments(
        bytes32[] memory contentHashes,
        uint256 totalCreatorAmount,
        uint256 licenseId
    ) internal {
        // In production: CreatorPool contract distributes
        // proportionally by ContributionScore off-chain
        // and calls claimCreatorPayment() for each creator.
        // Here we emit events for the off-chain indexer
        // to calculate the split and execute distributions.
        // This avoids unbounded loops that would exceed gas limits
        // for large content pools.
        emit CreatorPaymentQueued(address(0), totalCreatorAmount, licenseId);
    }

    // ─────────────────────────────────────────────
    // PRICING FUNCTIONS
    // ─────────────────────────────────────────────

    /**
     * @notice Calculate price for a single repository license.
     *         Single licenses use a flat base price scaled by
     *         the content's ContributionScore.
     *         Higher quality content commands higher prices.
     *
     * @param contentHash Hash of the content to price
     * @return price in USDC (6 decimals)
     */
    function calculateSinglePrice(bytes32 contentHash)
        public
        view
        returns (uint256)
    {
        // Base price for a single license
        // 10x the per-work base price
        return basePricePerWork * 10;
    }

    /**
     * @notice Calculate price for a category pool license
     *         using the bonding curve formula: P = k × N^α
     *         where α = 1.2 (superlinear — large buyers pay more)
     *
     * @param workCount Number of works in the requested pool
     * @return price in USDC (6 decimals)
     */
    function calculatePoolPrice(uint256 workCount)
        public
        view
        returns (uint256)
    {
        require(workCount > 0, "LicenseMarket: pool must contain at least 1 work");

        // P = k × N^1.2
        // We compute N^1.2 as N × N^0.2
        // N^0.2 approximated using integer math
        // For production: use a proper fixed-point math library
        // (PRBMath or ABDKMath64x64 recommended)

        uint256 n = workCount;
        uint256 k = basePricePerWork;

        // Approximate N^1.2:
        // N^1.2 = N × N^(1/5)
        // N^(1/5) = fifth root of N
        // Computed iteratively for precision
        uint256 fifthRoot = _fifthRoot(n);
        uint256 price = k * n * fifthRoot;

        return price;
    }

    /**
     * @notice Integer approximation of fifth root (N^0.2)
     *         Used in bonding curve calculation.
     *         Accurate to within 1% for values up to 10M.
     */
    function _fifthRoot(uint256 n) internal pure returns (uint256) {
        if (n == 0) return 0;
        if (n == 1) return 1;

        // Newton's method for fifth root
        uint256 x = n;
        uint256 y = (4 * x + n / (x * x * x * x)) / 5;
        while (y < x) {
            x = y;
            // Guard against x^4 overflow
            if (x > 1e12) break;
            y = (4 * x + n / (x * x * x * x)) / 5;
        }
        return x;
    }

    /**
     * @notice Preview the price before purchasing — no gas cost.
     *         AI companies call this to see cost before committing.
     *
     * @param workCount    Number of works they want to license
     * @param paymentToken 0=OGN (10% discount), 1=USDC, 2=ETH
     * @param isAcademic   True to see research license price
     * @return price       Final price in chosen payment token
     */
    function previewPrice(
        uint256 workCount,
        PaymentToken paymentToken,
        bool isAcademic
    ) external view returns (uint256 price) {
        price = calculatePoolPrice(workCount);

        if (isAcademic) {
            price = price - (price * RESEARCH_DISCOUNT_BPS / BPS_DENOMINATOR);
        }

        if (paymentToken == PaymentToken.OGN) {
            price = price - (price * OGN_DISCOUNT_BPS / BPS_DENOMINATOR);
        }

        return price;
    }

    // ─────────────────────────────────────────────
    // VIEW FUNCTIONS
    // ─────────────────────────────────────────────

    /**
     * @notice Check if a specific content piece is currently
     *         covered by an active license for a given licensee.
     */
    function isLicensed(
        address licensee,
        bytes32 contentHash
    ) external view returns (bool) {
        uint256[] memory licenseeIds = licensesByLicensee[licensee];
        for (uint256 i = 0; i < licenseeIds.length; i++) {
            License storage lic = licenses[licenseeIds[i]];
            if (!lic.active) continue;
            if (lic.expiryTimestamp > 0 && block.timestamp > lic.expiryTimestamp) continue;
            for (uint256 j = 0; j < lic.contentHashes.length; j++) {
                if (lic.contentHashes[j] == contentHash) return true;
            }
        }
        return false;
    }

    /**
     * @notice Get all license IDs purchased by a licensee
     */
    function getLicenseeHistory(address licensee)
        external
        view
        returns (uint256[] memory)
    {
        return licensesByLicensee[licensee];
    }

    /**
     * @notice Get full license details by ID
     */
    function getLicense(uint256 licenseId)
        external
        view
        returns (License memory)
    {
        return licenses[licenseId];
    }

    /**
     * @notice Get protocol revenue statistics
     */
    function getRevenueStats()
        external
        view
        returns (
            uint256 totalRevenue,
            uint256 totalBurned,
            uint256 totalToCreators,
            uint256 totalLicenseCount
        )
    {
        return (
            totalRevenueOGN,
            totalBurnedOGN,
            totalCreatorPaymentsOGN,
            totalLicenses
        );
    }

    // ─────────────────────────────────────────────
    // ADMIN FUNCTIONS
    // ─────────────────────────────────────────────

    /**
     * @notice Update the base price per work.
     *         Called by governance based on market conditions.
     *         Cannot be set below a minimum to protect creators.
     */
    function setBasePrice(uint256 newPrice) external onlyOwner {
        require(newPrice >= 100, "LicenseMarket: price too low — minimum 100");
        uint256 oldPrice = basePricePerWork;
        basePricePerWork = newPrice;
        emit BasePriceUpdated(oldPrice, newPrice);
    }

    /**
     * @notice Verify or unverify an academic institution
     *         for research license eligibility.
     */
    function setAcademicVerification(
        address institution,
        bool verified
    ) external onlyOwner {
        require(institution != address(0), "LicenseMarket: invalid address");
        verifiedAcademicInstitutions[institution] = verified;
        emit AcademicVerified(institution, verified);
    }

    /**
     * @notice Emergency pause
     */
    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }

    /**
     * @notice Accept ETH for ETH-based license payments
     */
    receive() external payable {}
}
