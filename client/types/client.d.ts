export function genKeyPair(): Promise<{
    packPrivkey0: bigint;
    packPrivkey1: bigint;
    packedPubkey0: bigint;
    packedPubkey1: bigint;
}>;
export function signData(data: any, privKey: any, signResponse: any): Promise<any[]>;
export function verifySignature(data: any, sig: any, pubKey: any, signResponse: any): Promise<any[]>;
