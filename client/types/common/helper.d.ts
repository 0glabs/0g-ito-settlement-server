export function calculatePedersenHash(nonce: any, userAddress: any, providerAddress: any): Promise<any>;
export function generateProofInput(requests: any, l: any, reqPubkey: any, reqSignBuff: any, resPubkey: any, resSignBuff: any): Promise<{
    serializedInput: any;
    reqSigner: any[];
    resSigner: any[];
    reqR8: any;
    reqS: any;
    resR8: any;
    resS: any;
}>;
export function signAndVerifyRequests(requests: any, babyJubJubPrivateKey: any, babyJubJubPublicKey: any, isRequest: any): Promise<{
    packPubkey: any;
    r8: any[];
    s: any[];
}>;
export function signRequests(requests: any, privKey: any, signResponse: any): Promise<any[]>;
export function verifySig(requests: any, sig: any, pubKey: any, signResponse: any): Promise<any[]>;
export function genPubkey(privkey: any): Promise<any>;
