const utils = require('./utils');

const ADDR_LENGTH = 20;
const NONCE_LENGTH = 8;
const FEE_LENGTH = 16; // u128 的长度为 16 字节

class Request {
    constructor(nonce, userAddress, providerAddress, resFee) {
        this.nonce = nonce ? BigInt(nonce) : BigInt(0);

        // userAddress 和 providerAddress 为 u160 以 hexstring 形式输入
        this.userAddress = userAddress ? BigInt(userAddress) : BigInt(0);
        this.providerAddress = providerAddress ? BigInt(providerAddress) : BigInt(0);

        this.resFee = resFee ? BigInt(resFee) : BigInt(0);
    }

    serializeRequest() {
        const buffer = new ArrayBuffer(NONCE_LENGTH + ADDR_LENGTH * 2);
        let offset = 0;

        // 写入 nonce (u64)
        const nonceBytes = utils.bigintToBytes(this.nonce, NONCE_LENGTH);
        console.log('nonceBytes:', nonceBytes, 'nonce:', this.nonce);
        new Uint8Array(buffer, offset, NONCE_LENGTH).set(nonceBytes);
        offset += NONCE_LENGTH;

        // 写入 userAddress (u160)
        const userAddressBytes = utils.bigintToBytes(this.userAddress, ADDR_LENGTH);
        new Uint8Array(buffer, offset, ADDR_LENGTH).set(userAddressBytes);
        offset += ADDR_LENGTH;

        // 写入 providerAddress (u160)
        const providerAddressBytes = utils.bigintToBytes(this.providerAddress, ADDR_LENGTH);
        new Uint8Array(buffer, offset, ADDR_LENGTH).set(providerAddressBytes);

        return new Uint8Array(buffer);
    }

    serializeResponse() {
        const buffer = new ArrayBuffer(FEE_LENGTH);
        let offset = 0;

        // 写入 resFee (u128)
        const resFeeBytes = utils.bigintToBytes(this.resFee, FEE_LENGTH);
        new Uint8Array(buffer, offset, FEE_LENGTH).set(resFeeBytes);

        return new Uint8Array(buffer);
    }

    serialize() {
        const requestBytes = this.serializeRequest();
        const responseBytes = this.serializeResponse();

        // 合并请求和响应的字节数组
        const combinedBytes = new Uint8Array(requestBytes.length + responseBytes.length);
        combinedBytes.set(requestBytes, 0);
        combinedBytes.set(responseBytes, requestBytes.length);

        return combinedBytes;
    }

    static deserialize(byteArray) {
        const expectedLength =
            NONCE_LENGTH + ADDR_LENGTH * 2 + FEE_LENGTH;

        if (byteArray.length !== expectedLength) {
            throw new Error(
                `Invalid byte array length for deserialization. Expected: ${expectedLength}, but got: ${byteArray.length}`
            );
        }

        const view = new DataView(byteArray.buffer);
        let offset = 0;

        // 读取 nonce (u64)
        const nonce = utils.bytesToBigint(
            new Uint8Array(byteArray.slice(offset, offset + NONCE_LENGTH))
        );
        offset += NONCE_LENGTH;

        // 读取 userAddress (u160)
        const userAddress = utils.bytesToBigint(
            new Uint8Array(byteArray.slice(offset, offset + ADDR_LENGTH))
        );
        offset += ADDR_LENGTH;

        // 读取 providerAddress (u160)
        const providerAddress = utils.bytesToBigint(
            new Uint8Array(byteArray.slice(offset, offset + ADDR_LENGTH))
        );
        offset += ADDR_LENGTH;

        // 读取 resFee (u128)
        const resFee = utils.bytesToBigint(
            new Uint8Array(byteArray.slice(offset, offset + FEE_LENGTH))
        );

        return new Request(
            nonce.toString(),
            '0x' + userAddress.toString(16),
            '0x' + providerAddress.toString(16),
            '0x' + resFee.toString()
        );
    }
}

module.exports = { Request, NONCE_LENGTH, ADDR_LENGTH, FEE_LENGTH };
