export class Request {
    static deserialize(byteArray: any): Request;
    constructor(nonce: any, reqFee: any, userAddress: any, providerAddress: any, requestHash: any, resFee: any);
    nonce: bigint;
    reqFee: bigint;
    userAddress: bigint;
    providerAddress: bigint;
    requestHash: any;
    resFee: bigint;
    serializeRequest(): Uint8Array;
    serializeResponse(): Uint8Array;
    serialize(): Uint8Array;
}
export const NONCE_LENGTH: 8;
export const ADDR_LENGTH: 20;
export const FEE_LENGTH: 16;
export const HASH_LENGTH: 32;
