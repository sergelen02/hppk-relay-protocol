// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract MessageRelayRegistry {
    struct Session {
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

    error SessionAlreadyExists();
    error SessionNotFound();
    error SessionAlreadyFinished();
    error InvalidRoute();
    error InvalidStep();
    error InvalidFrom();
    error InvalidTo();
    error InvalidPayloadHash();
    error InvalidPrevChainHash();
    error HopAlreadyExists();

    modifier onlyExistingSession(bytes32 sessionId) {
        if (!sessions[sessionId].exists) revert SessionNotFound();
        _;
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

        // 순서 검증
        if (step != s.currentStep + 1) revert InvalidStep();

        // route 검증
        if (step > s.route.length) revert InvalidStep();

        address expectedFrom = s.route[step - 1];
        address expectedTo = address(0);

        if (step < s.route.length) {
            expectedTo = s.route[step];
        }

        if (from != expectedFrom) revert InvalidFrom();
        if (to != expectedTo) revert InvalidTo();

        // 동일 payload 검증
        if (payloadHash != s.originPayloadHash) revert InvalidPayloadHash();

        // prevChainHash 연결 검증
        if (step == 1) {
            if (prevChainHash != bytes32(0)) revert InvalidPrevChainHash();
        } else {
            if (prevChainHash != s.latestChainHash) revert InvalidPrevChainHash();
        }

        // 여기서는 현재 ABI 일치와 저장 구조에 집중
        // 실제 완전 검증 단계에서는 아래 추가 가능:
        // 1) chainHash 재계산 검증
        // 2) HPPK verify(precompile 또는 verifier contract)
        // 3) pubKey 등록값과 일치 검증
        // 4) timestamp 검증
        // 5) localNonce 중복 검증

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

            emit SessionFinalized(
                sessionId,
                true,
                step,
                chainHash
            );
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
            bytes32 latestChainHash,
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
}