const eddsa = require('./crypto');
const utils = require('./utils');
const { Request, NONCE_LENGTH, ADDR_LENGTH } = require('./request');

async function generateProofInput(requests, l, resPubkey, resSignBuff) {
    await eddsa.init();


    const resR8 = [];
    const resS = [];
    for (let i = 0; i < resSignBuff.length; i++) {
        resR8.push(new Uint8Array(resSignBuff[i].slice(0, 32)));
        resS.push(new Uint8Array(resSignBuff[i].slice(32, 64)));
    }

    const paddingResult = await paddingSignature(requests, resR8, resS, l);

    const input = {
        serializedInput: paddingResult.serializedInputTrace,
        resSigner: [resPubkey[0].toString(16), resPubkey[1].toString(16)],
        resR8: paddingResult.resR8,
        resS: paddingResult.resS,
    };

    return input;
}

// 辅助函数：签名并验证请求
async function signAndVerifyRequests(
    requests,
    babyJubJubPrivateKey,
    babyJubJubPublicKey,
    isRequest
) {
    await eddsa.init();

    const packPubkey = eddsa.packPoint(babyJubJubPublicKey);
    const signatures = [];
    const r8 = [];
    const s = [];

    var serializedInputTrace = [];
    if (isRequest) {
        serializedInputTrace = requests.map((request) => request.serializeRequest());
    } else {
        serializedInputTrace = requests.map((request) => request.serializeResponse());
    }

    for (let i = 0; i < serializedInputTrace.length; i++) {
        const signature = await eddsa.babyJubJubSignature(
            serializedInputTrace[i],
            babyJubJubPrivateKey
        );
        signatures.push(signature);

        const isValid = await eddsa.babyJubJubVerify(
            serializedInputTrace[i],
            signature,
            babyJubJubPublicKey
        );
        console.log('Signature', i, 'is valid:', isValid);

        const packedSig = eddsa.packSignature(signature);
        r8.push(packedSig.slice(0, 32));
        s.push(packedSig.slice(32, 64));
    }
    return { packPubkey, r8, s };
}

async function signRequestHelper(trace, privkey) {
    const sigs = [];
    for (let i = 0; i < trace.length; i++) {
        const signature = await eddsa.babyJubJubSignature(trace[i], privkey);
        sigs.push(eddsa.packSignature(signature));
    }
    return sigs;
}

async function signRequests(requests, privKey, signResponse) {
    await eddsa.init();

    var trace;
    if (signResponse) {
        trace = requests.map((request) => request.serializeResponse());
    } else {
        trace = requests.map((request) => request.serializeRequest());
    }

    return await signRequestHelper(trace, privKey);
}

async function verifySigHelper(trace, sigs, pubkey) {
    const unpackPubkey = new Uint8Array(32);
    unpackPubkey.set(utils.bigintToBytes(BigInt(pubkey[0]), 16), 0);
    unpackPubkey.set(utils.bigintToBytes(BigInt(pubkey[1]), 16), 16);
    const unpackedPubkey = eddsa.unpackPoint(unpackPubkey);

    const isValid = [];
    for (let i = 0; i < trace.length; i++) {
        const unpackSignature = eddsa.unpackSignature(new Uint8Array(sigs[i]));
        isValid.push(await eddsa.babyJubJubVerify(trace[i], unpackSignature, unpackedPubkey));
    }
    return isValid;
}

async function verifySig(requests, sig, pubKey, signResponse) {
    await eddsa.init();

    var trace;
    if (signResponse) {
        trace = requests.map((request) => request.serializeResponse());
    } else {
        trace = requests.map((request) => request.serializeRequest());
    }

    return await verifySigHelper(trace, sig, pubKey);
}

// 辅助函数：填充签名
async function paddingSignature(requests, resR8, resS, l) {
    if (l < requests.length) {
        throw new Error('l must be greater than or equal to the length of serializedInputTrace');
    }

    const lastRequest = requests[requests.length - 1];

    const lastResR8 = resR8[resR8.length - 1];
    const lastResS = resS[resS.length - 1];

    let currentNonce = lastRequest.nonce;

    for (let i = requests.length; i < l; i++) {
        currentNonce += BigInt(1);
        const noopRequest = new Request(
            currentNonce,
            '0x' + lastRequest.userAddress.toString(16),
            '0x' + lastRequest.providerAddress.toString(16),
            0
        );

        requests.push(noopRequest);

        resR8.push(lastResR8);
        resS.push(lastResS);
    }

    const serializedInputTrace = requests.map((request) => request.serialize());
    return { serializedInputTrace, resR8, resS };
}

async function genPubkey(privkey) {
    await eddsa.init();

    return eddsa.babyJubJubGeneratePublicKey(privkey);
}

module.exports = {
    generateProofInput,
    signAndVerifyRequests,
    signRequests,
    verifySig,
    genPubkey,
};
