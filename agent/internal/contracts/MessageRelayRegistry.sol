// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IHPPKVerifier {
    function verify(
        bytes calldata pubKey,
        bytes32 messageHash,
        bytes calldata signature
    ) external view returns (bool);
}

contract MessageRelayRegistry {
    struct Session 
        bool exists;
        bool finished;
        bool valid;
        bytes32 originPayloadHash;
        bytes32 latestChainHash;
        uint256 currentStep;
        address[] route;
    }

    struct HopRecord {
        uint256 step;
        address from;
        address to;
        bytes32 payloadHash;
        bytes32 prevChainHash;
        bytes32 chainHash;
        uint256 localNonce;
        bytes pubKey;
        bytes signature;
        uint256 timestampUnix;
        bytes32 metaHash;
        bool exists;
    }

    mapping(bytes32 => Session) private sessions;
    mapping(bytes32 => mapping(uint256 => HopRecord)) private hops;

    mapping(address => bytes32) public registeredPubKeyHash;
    mapping(bytes32 => mapping(address => mapping(uint256 => bool))) public usedNonce;

    address public owner;
    address public hppkVerifier;
    bool public hppkVerificationEnabled;

    uint256 public constant MAX_FUTURE_SKEW = 30 seconds;
    uint256 public constant MAX_PAST_DELAY = 10 minutes;

    event PubKeyRegistered(address indexed user, bytes32 indexed pubKeyHash);
    event HPPKVerifierUpdated(address indexed verifier, bool enabled);

    event SessionCreated(
        bytes32 indexed sessionId,
        bytes32 indexed originPayloadHash,
        uint256 routeLength
    );

    event HopSubmitted(
        bytes32 indexed sessionId,
        uint256 indexed step,
        address indexed from,
        address to,
        bytes32 payloadHash,
        bytes32 prevChainHash,
        bytes32 chainHash,
        uint256 localNonce,
        uint256 timestampUnix,
        bytes32 metaHash
    );

    event SessionFinalized(
        bytes32 indexed sessionId,
        bool valid,
        uint256 finalStep,
        bytes32 finalChainHash
    );

    error NotOwner();
    error SessionAlreadyExists();
    error SessionNotFound();
    error SessionAlreadyFinished();
    error InvalidRoute();
    error InvalidStep();
    error InvalidFrom();
    error InvalidTo();
    error InvalidPayloadHash();
    error InvalidPrevChainHash();
    error InvalidChainHash();
    error HopAlreadyExists();
    error PubKeyNotRegistered();
    error PubKeyMismatch();
    error NonceAlreadyUsed();
    error InvalidTimestamp();
    error HPPKVerifierNotSet();
    error InvalidHPPKSignature();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyExistingSession(bytes32 sessionId) {
        if (!sessions[sessionId].exists) revert SessionNotFound();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setHPPKVerifier(address verifier, bool enabled) external onlyOwner {
        hppkVerifier = verifier;
        hppkVerificationEnabled = enabled;

        emit HPPKVerifierUpdated(verifier, enabled);
    }

    function registerPubKey(bytes calldata pubKey) external {
        require(pubKey.length > 0, "empty pubKey");

        bytes32 pubKeyHash = keccak256(pubKey);
        registeredPubKeyHash[msg.sender] = pubKeyHash;

        emit PubKeyRegistered(msg.sender, pubKeyHash);
    }

    function createSession(
        bytes32 sessionId,
        bytes32 originPayloadHash,
        address[] calldata route
    ) external {
        if (sessions[sessionId].exists) revert SessionAlreadyExists();
        if (sessionId == bytes32(0)) revert SessionNotFound();
        if (originPayloadHash == bytes32(0)) revert InvalidPayloadHash();
        if (route.length == 0) revert InvalidRoute();

        for (uint256 i = 0; i < route.length; i++) {
            if (route[i] == address(0)) revert InvalidRoute();
        }

        Session storage s = sessions[sessionId];
        s.exists = true;
        s.finished = false;
        s.valid = false;
        s.originPayloadHash = originPayloadHash;
        s.latestChainHash = bytes32(0);
        s.currentStep = 0;

        for (uint256 i = 0; i < route.length; i++) {
            s.route.push(route[i]);
        }

        emit SessionCreated(sessionId, originPayloadHash, route.length);
    }

    function recomputeChainHash(
        bytes32 sessionId,
        uint256 step,
        address from,
        address to,
        bytes32 payloadHash,
        bytes32 prevChainHash,
        uint256 localNonce,
        uint256 timestampUnix,
        bytes32 metaHash
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                sessionId,
                step,
                from,
                to,
                payloadHash,
                prevChainHash,
                localNonce,
                timestampUnix,
                metaHash
            )
        );
    }

    function submitHop(
        bytes32 sessionId,
        uint256 step,
        address from,
        address to,
        bytes32 payloadHash,
        bytes32 prevChainHash,
        bytes32 chainHash,
        uint256 localNonce,
        bytes calldata pubKey,
        bytes calldata signature,
        uint256 timestampUnix,
        bytes32 metaHash
    ) external onlyExistingSession(sessionId) {
        Session storage s = sessions[sessionId];

        if (s.finished) revert SessionAlreadyFinished();
        if (step == 0) revert InvalidStep();
        if (hops[sessionId][step].exists) revert HopAlreadyExists();

        if (step != s.currentStep + 1) revert InvalidStep();
        if (step > s.route.length) revert InvalidStep();

        address expectedFrom = s.route[step - 1];
        address expectedTo = address(0);

        if (step < s.route.length) {
            expectedTo = s.route[step];
        }

        if (from != expectedFrom) revert InvalidFrom();
        if (to != expectedTo) revert InvalidTo();

        if (payloadHash != s.originPayloadHash) revert InvalidPayloadHash();

        if (step == 1) {
            if (prevChainHash != bytes32(0)) revert InvalidPrevChainHash();
        } else {
            if (prevChainHash != s.latestChainHash) revert InvalidPrevChainHash();
        }

        bytes32 recomputed = recomputeChainHash(
            sessionId,
            step,
            from,
            to,
            payloadHash,
            prevChainHash,
            localNonce,
            timestampUnix,
            metaHash
        );

        if (chainHash != recomputed) revert InvalidChainHash();

        bytes32 registeredHash = registeredPubKeyHash[from];
        if (registeredHash == bytes32(0)) revert PubKeyNotRegistered();

        bytes32 inputPubKeyHash = keccak256(pubKey);
        if (inputPubKeyHash != registeredHash) revert PubKeyMismatch();

        if (usedNonce[sessionId][from][localNonce]) revert NonceAlreadyUsed();
        usedNonce[sessionId][from][localNonce] = true;

        _validateTimestamp(timestampUnix);
        _verifyHPPK(pubKey, chainHash, signature);

        hops[sessionId][step] = HopRecord({
            step: step,
            from: from,
            to: to,
            payloadHash: payloadHash,
            prevChainHash: prevChainHash,
            chainHash: chainHash,
            localNonce: localNonce,
            pubKey: pubKey,
            signature: signature,
            timestampUnix: timestampUnix,
            metaHash: metaHash,
            exists: true
        });

        s.latestChainHash = chainHash;
        s.currentStep = step;

        emit HopSubmitted(
            sessionId,
            step,
            from,
            to,
            payloadHash,
            prevChainHash,
            chainHash,
            localNonce,
            timestampUnix,
            metaHash
        );

        if (step == s.route.length) {
            s.finished = true;
            s.valid = true;

            emit SessionFinalized(sessionId, true, step, chainHash);
        }
    }

    function _validateTimestamp(uint256 timestampUnix) internal view {
        if (timestampUnix > block.timestamp + MAX_FUTURE_SKEW) {
            revert InvalidTimestamp();
        }

        if (timestampUnix + MAX_PAST_DELAY < block.timestamp) {
            revert InvalidTimestamp();
        }
    }

    function _verifyHPPK(
        bytes calldata pubKey,
        bytes32 messageHash,
        bytes calldata signature
    ) internal view {
        if (!hppkVerificationEnabled) {
            return;
        }

        if (hppkVerifier == address(0)) {
            revert HPPKVerifierNotSet();
        }

        bool ok = IHPPKVerifier(hppkVerifier).verify(
            pubKey,
            messageHash,
            signature
        );

        if (!ok) {
            revert InvalidHPPKSignature();
        }
    }

    function getSession(bytes32 sessionId)
        external
        view
        onlyExistingSession(sessionId)
        returns (
            bool exists,
            bool finished,
            bool valid,
            bytes32 originPayloadHash,
            bytes32 latestChainHash_,
            uint256 currentStep,
            uint256 routeLength
        )
    {
        Session storage s = sessions[sessionId];
        return (
            s.exists,
            s.finished,
            s.valid,
            s.originPayloadHash,
            s.latestChainHash,
            s.currentStep,
            s.route.length
        );
    }

    function getRouteAt(bytes32 sessionId, uint256 index)
        external
        view
        onlyExistingSession(sessionId)
        returns (address)
    {
        Session storage s = sessions[sessionId];
        require(index < s.route.length, "route index out of bounds");
        return s.route[index];
    }

    function getHop(bytes32 sessionId, uint256 step)
        external
        view
        onlyExistingSession(sessionId)
        returns (
            uint256 hopStep,
            address from,
            address to,
            bytes32 payloadHash,
            bytes32 prevChainHash,
            bytes32 chainHash,
            uint256 localNonce,
            bytes memory pubKey,
            bytes memory signature,
            uint256 timestampUnix,
            bytes32 metaHash,
            bool exists
        )
    {
        HopRecord storage h = hops[sessionId][step];
        return (
            h.step,
            h.from,
            h.to,
            h.payloadHash,
            h.prevChainHash,
            h.chainHash,
            h.localNonce,
            h.pubKey,
            h.signature,
            h.timestampUnix,
            h.metaHash,
            h.exists
        );
    }

    function isPayloadIntact(bytes32 sessionId)
        external
        view
        onlyExistingSession(sessionId)
        returns (bool)
    {
        Session storage s = sessions[sessionId];
        if (s.currentStep == 0) {
            return false;
        }

        HopRecord storage h = hops[sessionId][s.currentStep];
        return h.payloadHash == s.originPayloadHash;
    }

    function currentHop(bytes32 sessionId)
        external
        view
        onlyExistingSession(sessionId)
        returns (uint256)
    {
        return sessions[sessionId].currentStep;
    }

    function latestChainHash(bytes32 sessionId)
        external
        view
        onlyExistingSession(sessionId)
        returns (bytes32)
    {
        return sessions[sessionId].latestChainHash;
    }

    function getRegisteredPubKeyHash(address user) external view returns (bytes32) {
        return registeredPubKeyHash[user];
    }

    function isNonceUsed(
        bytes32 sessionId,
        address user,
        uint256 localNonce
    ) external view returns (bool) {
        return usedNonce[sessionId][user][localNonce];
    }
}