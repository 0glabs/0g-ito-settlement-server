pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "./settlement_eddsa/commit_account.circom";
include "./hasher/pedersen_bytes.circom";
include "./settlement_eddsa/check_balance.circom";
include "./settlement_eddsa/check_nonce.circom";
include "./settlement_eddsa/verify_request_signature.circom";
include "./settlement_eddsa/verify_response_signature.circom";
include "./utils/bytes_to_num.circom";

// l: trace length
template SettleTrace(l) {
    var i;
    var j; 
    
    var nonceBytesWidth = 8; // unit32:[u8;8]
    var addressBytesWidth = 20; // unit160:[u8; 20]
    var balanceBytesWidth = 16; // unit128:[u8; 16]
    var requestBytesWidth = nonceBytesWidth + addressBytesWidth * 2 + balanceBytesWidth; // nonce + userAddress + itoAddress + fee

    // request content
    // every settlment just process one account, so the reqSigner should be same

    signal input serializedInput[l][requestBytesWidth];

    signal input resSigner[2];
    signal input resR8[l][32];
    signal input resS[l][32];

    component reqSigVerifier = SignatureVerify(l);
    for (i=0; i<l; i++) {
        for (j=0; j<requestBytesWidth; j++) {
            reqSigVerifier.serializedRequest[i][j] <== serializedInput[i][j];
        }
    }

    signal output userAddress;
    signal output itoAddress;
    userAddress <== reqSigVerifier.userAddress[0];
    itoAddress <== reqSigVerifier.itoAddress[0];

    // verify response signature
    // component resSigVerifier = ResponseSignatureVerify(l);
    // for (i=0; i<l; i++) {
    //     for (j=0; j<responseBytesWidth; j++) {
    //         resSigVerifier.serializedResponse[i][j] <== serializedInput[i][requestBytesWidth + j];
    //     }
    // }
    // resSigVerifier.r8 <== resR8;
    // resSigVerifier.s <== resS;
    // component resUnpackSigner0 = Num2Bytes(16);
    // component resUnpackSigner1 = Num2Bytes(16);
    // resUnpackSigner0.in <== resSigner[0];
    // resUnpackSigner1.in <== resSigner[1];
    // for (i=0; i<16; i++) {
    //     resSigVerifier.signer[i] <== resUnpackSigner0.out[i];
    //     resSigVerifier.signer[16 + i] <== resUnpackSigner1.out[i];
    // }

    // check nonce is valid
    component checkNonce = NonceCheck(l);
    checkNonce.nonce <== reqSigVerifier.nonce;
    signal output initNonce;
    signal output finalNonce;
    initNonce <== checkNonce.initNonce;
    finalNonce <== checkNonce.finalNonce;

    // check balance trace is valid
    component checkBalance = BalanceCheck(l);
    checkBalance.fee <== reqSigVerifier.fee;
    
    signal output totalFee;
    totalFee <== checkBalance.totalFee;
}
