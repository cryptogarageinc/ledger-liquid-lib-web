/* eslint-disable require-jsdoc */
// import * as TransportNodeHid from '@ledgerhq/hw-transport-node-hid';
// const TransportNodeHid = require('@ledgerhq/hw-transport-node-hid').default;
const TransportWebUSB = require('@ledgerhq/hw-transport-webusb').default;
// const cfdjs = require('cfd-js');
const Ripemd160 = require('ripemd160');
const sha = require('sha.js');
const base58 = require('bs58');

function byteToString(buffer) {
  // return buffer.toString();
  return (new TextDecoder).decode(buffer);
}

function byteToHexString(buffer) {
  // return buffer.toString('hex');
  return Array.from(buffer).map((v) => {
    let str = v.toString(16);
    if (str.length === 1) str = '0' + str;
    return str;
  }).join('');
}

function readUInt16BE(buf, offset) {
  // return buf.readUInt16BE(offset);
  if (buf.length <= offset + 1) {
    throw Error('offset range error.');
  }
  let result = buf[offset] << 8;
  result |= buf[offset + 1];
  return result >>> 0;
}

function readUInt16LE(buf, offset) {
  let result = 0;
  if (buf.length <= offset + 1) {
    throw Error('offset range error.');
  }
  result = buf[offset];
  result |= buf[offset + 1] << 8;
  return result >>> 0;
}

function readUInt32LE(buf, offset) {
  let result = 0;
  if (buf.length <= offset + 3) {
    throw Error('offset range error.');
  }
  result |= buf[offset];
  result |= buf[offset + 1] << 8;
  result |= buf[offset + 2] << 16;
  result |= buf[offset + 3] << 24;
  return result >>> 0;
}

function readUInt64BE(buf, offset) {
  let result = 0;
  if (buf.length <= offset + 7) {
    throw Error('offset range error.');
  }
  result |= buf[offset + 7];
  result |= buf[offset + 6] << 8;
  result |= buf[offset + 5] << 16;
  result |= buf[offset + 4] << 24;
  result |= buf[offset + 3] << 32;
  result |= buf[offset + 2] << 40;
  result |= buf[offset + 1] << 48;
  result |= buf[offset] << 56;
  return result >>> 0;
}

function writeUInt16LE(buf, value, offset) {
  const wrBuf = Buffer.from([value & 0x00ff, ((value >> 8) & 0x00ff)]);
  buf[offset] = wrBuf[0];
  buf[offset + 1] = wrBuf[1];
  return buf;
}

function writeUInt32LE(buf, value, offset) {
  const wrBuf = Buffer.from([
    value & 0x00ff,
    ((value >> 8) & 0x00ff),
    ((value >> 16) & 0x00ff),
    ((value >> 24) & 0x00ff),
  ]);
  buf[offset] = wrBuf[0];
  buf[offset + 1] = wrBuf[1];
  buf[offset + 2] = wrBuf[2];
  buf[offset + 3] = wrBuf[3];
  return buf;
}

function writeUInt32BE(buf, value, offset) {
  const wrBuf = Buffer.from([
    ((value >> 24) & 0x00ff),
    ((value >> 16) & 0x00ff),
    ((value >> 8) & 0x00ff),
    value & 0x00ff,
  ]);
  buf[offset] = wrBuf[0];
  buf[offset + 1] = wrBuf[1];
  buf[offset + 2] = wrBuf[2];
  buf[offset + 3] = wrBuf[3];
  return buf;
}

function hash160(buf) {
  const sha256Hash = sha('sha256').update(buf).digest();
  return (new Ripemd160()).update(sha256Hash).digest();
}

function sha256d(buf) {
  const sha256Hash = sha('sha256').update(buf).digest();
  return sha('sha256').update(sha256Hash).digest();
}

function encodeBase58Check(buf) {
  const checksum = sha256d(buf);
  return base58.encode(Buffer.concat([buf, checksum], buf.length + 4));
}

function createExtPubKey(
    networkType, depth, childNumber, chainCode, publicKey, parentPubkey) {
  let version = '043587cf'; // testnet
  if ((networkType === 'mainnet') || (networkType === 'liquidv1')) {
    version = '0488b21e'; // mainnet
  }
  const parentKeyBuf = Buffer.from(parentPubkey, 'hex');
  const fingerprint = byteToHexString(hash160(parentKeyBuf).subarray(0, 4));
  const depthStr = byteToHexString(Buffer.from([depth]));
  let numberBuf = Buffer.alloc(4);
  numberBuf = writeUInt32BE(numberBuf, childNumber, 0);
  const childStr = byteToHexString(numberBuf);

  const xpubHex = [
    version, depthStr, fingerprint, childStr, chainCode, publicKey,
  ].join('');
  return encodeBase58Check(Buffer.from(xpubHex, 'hex'));
};

function readVarIntFromBuffer(buffer, startOffset) {
  let result;
  let size = 1;
  if (buffer[startOffset] < 0xfd) {
    result = buffer[startOffset];
  } else if (buffer[startOffset] === 0xfd) {
    result = readUInt16LE(buffer, startOffset + 1);
    size = 3;
  } else if (buffer[startOffset] === 0xfe) {
    result = readUInt32LE(buffer, startOffset + 1);
    size = 5;
  } else {
    const high = buffer.subarray(startOffset + 1, startOffset + 1 + 4);
    const low = buffer.subarray(startOffset + 5, startOffset + 5 + 4);
    result = readUInt32LE(high, 0) << 32;
    result |= readUInt32LE(low, 0);
    size = 9;
  }
  return {value: result, size: size};
}

function reverseBuffer(buf) {
  const buffer = Buffer.allocUnsafe(buf.length);
  for (let i = 0, j = buf.length - 1; i <= j; ++i, --j) {
    buffer[i] = buf[j];
    buffer[j] = buf[i];
  }
  return buffer;
}

function decodeRawTransaction(proposalTx) {
  const buffer = Buffer.from(proposalTx, 'hex');
  const txin = [];
  const txout = [];
  const version = readUInt32LE(buffer, 0);
  let offset = 4;
  // const useWitness = (buffer[offset] !== 0);
  ++offset;

  const txinVarNum = readVarIntFromBuffer(buffer, offset);
  const txinNum = txinVarNum.value;
  offset += txinVarNum.size;
  for (let index = 0; index < txinNum; ++index) {
    const txid = byteToHexString(
        reverseBuffer(buffer.subarray(offset, offset + 32)));
    offset += 32;
    const utxoVout = readUInt32LE(buffer, offset);
    offset += 4;
    const scriptsigLenData = readVarIntFromBuffer(buffer, offset);
    const scriptsigLen = scriptsigLenData.value;
    offset += scriptsigLenData.size;
    offset += scriptsigLen;
    const sequence = readUInt32LE(buffer, offset);
    offset += 4;
    const txinData = {
      txid: txid,
      vout: utxoVout & 0x3fffffff,
      sequence: sequence,
    };
    if ((utxoVout & 0x80000000) !== 0) {
      const assetBlindingNonce = byteToHexString(
          reverseBuffer(buffer.subarray(offset, offset + 32)));
      offset += 32;
      const assetEntropy = byteToHexString(
          reverseBuffer(buffer.subarray(offset, offset + 32)));
      offset += 32;
      let assetAmount;
      if (buffer[offset] <= 1) {
        assetAmount = byteToHexString(buffer.subarray(offset, offset + 9));
        offset += 9;
      } else {
        assetAmount = byteToHexString(buffer.subarray(offset, offset + 33));
        offset += 33;
      }
      let token;
      if (buffer[offset] === 0) {
        token = '';
        offset += 1;
      } else if (buffer[offset] === 1) {
        token = byteToHexString(buffer.subarray(offset, offset + 9));
        offset += 9;
      } else {
        token = byteToHexString(buffer.subarray(offset, offset + 33));
        offset += 33;
      }
      let issuance;
      if (assetBlindingNonce === '0000000000000000000000000000000000000000000000000000000000000000') {
        issuance = {
          assetBlindingNonce: assetBlindingNonce,
          contractHash: assetEntropy,
          assetamountcommitment: assetAmount,
        };
      } else {
        issuance = {
          assetBlindingNonce: assetBlindingNonce,
          assetEntropy: assetEntropy,
          assetamountcommitment: assetAmount,
        };
      }
      if (token) {
        issuance['tokenamountcommitment'] = token;
      }
      txinData['issuance'] = issuance;
    }
    txin.push(txinData);
  }

  const txoutVarNum = readVarIntFromBuffer(buffer, offset);
  const txoutNum = txoutVarNum.value;
  offset += txoutVarNum.size;
  for (let index = 0; index < txoutNum; ++index) {
    let txoutData = {};
    if (buffer[offset] === 0x01) {
      // unblind
      const asset = byteToHexString(reverseBuffer(
          buffer.subarray(offset + 1, offset + 1 + 32)));
      offset += 33;
      const value = readUInt64BE(buffer, offset + 1);
      offset += 9;
      offset += (buffer[offset] === 0x00) ? 1 : 33; // nonce
      const scriptPubkeyLenData = readVarIntFromBuffer(buffer, offset);
      const scriptPubkeyLen = scriptPubkeyLenData.value;
      offset += scriptPubkeyLenData.size;
      const scriptPubKey = byteToHexString(buffer.subarray(
          offset, offset + scriptPubkeyLen));
      offset += scriptPubkeyLen;
      txoutData = {
        asset: asset,
        value: value,
        scriptPubKey: {
          hex: scriptPubKey,
        },
      };
    } else {
      // blind
      const assetcommitment = byteToHexString(buffer.subarray(
          offset, offset + 33));
      offset += 33;
      const valuecommitment = byteToHexString(buffer.subarray(
          offset, offset + 33));
      offset += 33;
      const commitmentnonce = byteToHexString(buffer.subarray(
          offset, offset + 33));
      offset += 33;
      const scriptPubkeyLenData = readVarIntFromBuffer(buffer, offset);
      const scriptPubkeyLen = scriptPubkeyLenData.value;
      offset += scriptPubkeyLenData.size;
      const scriptPubKey = byteToHexString(buffer.subarray(
          offset, offset + scriptPubkeyLen));
      offset += scriptPubkeyLen;
      txoutData = {
        assetcommitment: assetcommitment,
        valuecommitment: valuecommitment,
        commitmentnonce: commitmentnonce,
        scriptPubKey: {
          hex: scriptPubKey,
        },
      };
    }
    txout.push(txoutData);
  }

  const locktime = readUInt32LE(buffer, offset);
  return {
    version: version,
    locktime: locktime,
    vin: txin,
    vout: txout,
  };
  ;
}

// ---- ledger-liquid-lib ----

function convertErrorCode(buf) {
  return readUInt16BE(buf, 0);
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function debugSendLog(funcName, buffer) {
  // console.log(funcName, buffer.toString('hex'));
}

function getVarIntBuffer(num) {
  let buf;
  if (num < 0xfd) {
    buf = Buffer.from([num]);
  } else if (num <= 0xffff) {
    buf = Buffer.from([0xfd, 0, 0]);
    buf = writeUInt16LE(buf, num, 1);
  } else if (num <= 0xffffffff) {
    buf = Buffer.from([0xfe, 0, 0, 0, 0]);
    buf = writeUInt32LE(buf, num, 1);
  } else {
    buf = Buffer.from([0xff, 0, 0, 0, 0, 0, 0, 0, 0]);
    const high = num >> 32;
    const low = num & 0xffffffff;
    buf = writeUInt32LE(buf, low, 1);
    buf = writeUInt32LE(buf, high, 5);
  }
  return buf;
}

function convertValueFromAmount(amount) {
  let value = Buffer.alloc(9);
  value[0] = 1;
  let high;
  let low;
  if (typeof amount === 'bigint') {
    const bigHigh = (amount > BigInt(0xffffffff)) ?
        (amount >> BigInt(32)) : BigInt(0);
    const bigLow = amount & BigInt(0xffffffff);
    high = Number(bigHigh);
    low = Number(bigLow);
  } else {
    high = (amount > 0xffffffff) ? (amount >> 32) : 0;
    low = amount & 0xffffffff;
  }
  value = writeUInt32BE(value, high, 1);
  value = writeUInt32BE(value, low, 5);
  return value;
}

function parseBip32Path(path, parent = false) {
  if (path === '') {
    return Buffer.alloc(0);
  }

  let targetPath = path;
  if (targetPath.startsWith('m/')) {
    targetPath = targetPath.substring(2);
  }
  const items = targetPath.split('/');
  if (items.length > 10) {
    throw new Error('Out of Range. Number of BIP 32 derivations to perform is up to 10.');
  }
  const hardendedTargets = ['\'', 'h', 'H'];

  const length = (parent) ? items.length - 1 : items.length;
  let buf = Buffer.alloc(length * 4);
  const array = [];
  for (let idx = 0; idx < length; ++idx) {
    let isFind = false;
    for (let hIdx = 0; hIdx < hardendedTargets.length; ++hIdx) {
      const hKey = hardendedTargets[hIdx];
      const item = items[idx].split(hKey);
      if (item.length > 1) {
        const num = Number(item[0]);
        if ((num === Number.NaN) || (item[1] !== '') || (item.length.length > 2)) {
          throw new Error(`Illegal path format. [${item[0]},${item[1]}]`);
        }
        // const value = 0x80000000 | num;
        const value = 2147483648 + num;
        array.push(value);
        buf = writeUInt32BE(buf, value, idx * 4);
        isFind = true;
        break;
      }
    }
    if (!isFind) {
      const num = Number(items[idx]);
      if (num === Number.NaN) throw new Error(`Illegal path format. [${items[idx]}]`);
      array.push(num);
      buf = writeUInt32BE(buf, num, idx * 4);
    }
  }
  // console.log('bip32 path => ', buf);
  return {
    buffer: buf,
    array: array,
  };
}

// GET WALLET PUBLIC KEY
async function getWalletPublicKey(
    transport, path, option, parent = false) {
  const CLA = 0xe0;
  const GET_WALLET_PUBLIC_KEY = 0x40;
  const p1 = 0;

  const pathBuffer = parseBip32Path(path, parent).buffer;

  const data = Buffer.concat([
    Buffer.from([pathBuffer.length / 4]),
    pathBuffer]);
  debugSendLog('getWalletPublicKey send -> ', data);
  const apdu = Buffer.concat(
      [Buffer.from([CLA, GET_WALLET_PUBLIC_KEY, p1, option]),
        Buffer.from([data.length]), data]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ?
      exchangeRet : exchangeRet.subarray(exchangeRet.length - 2);
  let pubkey = '';
  let chainCode = '';
  let pubkeyLength = 0;
  let addressLength = 0;
  let address = '';
  if (exchangeRet.length > 2) {
    pubkeyLength = exchangeRet[0];
    if (pubkeyLength === 65) {
      pubkey = byteToHexString(exchangeRet.subarray(1, 66));
    } else if (exchangeRet[0] === 33) {
      pubkey = byteToHexString(exchangeRet.subarray(1, 34));
    }
    if (exchangeRet.length > (pubkeyLength + 1 + 2)) {
      // address length
      addressLength = exchangeRet[pubkeyLength + 1];
      if (addressLength > 0) {
        const addrOffset = pubkeyLength + 2;
        address = byteToString(
            exchangeRet.subarray(addrOffset, addrOffset + addressLength));
      }
    }
    if (exchangeRet.length >= (pubkeyLength + addressLength + 2 + 32 + 2)) {
      const codeChainOffset = pubkeyLength + addressLength + 2;
      chainCode = byteToHexString(
          exchangeRet.subarray(codeChainOffset, codeChainOffset + 32));
    }
  }

  return {
    errorCode: convertErrorCode(result),
    pubkey: pubkey,
    chainCode: chainCode,
    address: address,
  };
}

// GET COIN VERSION
async function getCoinVersion(transport) {
  const CLA = 0xe0;
  const GET_COIN_VERSION = 0x16;
  const apdu = Buffer.from([CLA, GET_COIN_VERSION, 0, 0, 0]);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  let prefixP2pkh = 0;
  let prefixP2sh = 0;
  let coinFamily = 0;
  let coinName = '';
  let coinTicker = '';
  if (exchangeRet.length >= 9) {
    prefixP2pkh = readUInt16BE(exchangeRet, 0);
    prefixP2sh = readUInt16BE(exchangeRet, 2);
    coinFamily = exchangeRet[4];
    const coinNameLen = exchangeRet[5];
    if (coinNameLen > 0) {
      const coinNameArr = exchangeRet.subarray(6, 6 + coinNameLen);
      coinName = byteToString(coinNameArr);
    }
    const offset = 6 + coinNameLen;
    if (offset < exchangeRet.length) {
      const coinTickerLen = exchangeRet[offset];
      if (coinTickerLen > 0) {
        const coinTickerArr = exchangeRet.subarray(
            offset + 1, offset + 1 + coinTickerLen);
        coinTicker = byteToString(coinTickerArr);
      }
    }
  }
  const errorCode = convertErrorCode(result);
  return {
    errorCode: errorCode,
    prefixP2pkh: prefixP2pkh,
    prefixP2sh: prefixP2sh,
    coinFamily: coinFamily,
    coinName: coinName,
    coinTicker: coinTicker,
  };
}

async function liquidSetupHeadless(transport, authorizationPublicKeyHex) {
  const ADM_CLA = 0xd0;
  const LIQUID_SETUP_HEADLESS = 0x02;
  const authPubkeyData = Buffer.from(authorizationPublicKeyHex, 'hex');
  const apdu = Buffer.concat(
      [Buffer.from([ADM_CLA, LIQUID_SETUP_HEADLESS, 0, 0]),
        Buffer.from([authPubkeyData.length]), authPubkeyData]);
  const exchangeRet = await transport.exchange(apdu);
  return convertErrorCode(exchangeRet);
}

async function sendHashInputStartCmd(transport, p1, p2, data) {
  // FIXME split send.
  const CLA = 0xe0;
  const HASH_INPUT_START = 0x44;
  const apdu = Buffer.concat([Buffer.from([CLA, HASH_INPUT_START, p1, p2]),
    Buffer.from([data.length]), data]);
  debugSendLog('sendHashInputStartCmd send -> ', apdu);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
    exchangeRet.subarray(0, exchangeRet.length - 2);
  return {data: resultData, errorCode: convertErrorCode(result)};
}

async function sendHashInputFinalizeFullCmd(transport, p1, p2, data) {
  // FIXME split send.
  const CLA = 0xe0;
  const HASH_INPUT_FINALIZE_FULL = 0x4a;
  const apdu = Buffer.concat(
      [Buffer.from([CLA, HASH_INPUT_FINALIZE_FULL, p1, p2]),
        Buffer.from([data.length]), data]);
  debugSendLog('sendHashInputFinalizeFullCmd send -> ', apdu);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
    exchangeRet.subarray(0, exchangeRet.length - 2);
  const ecode = convertErrorCode(result);
  if (ecode != 0x9000) {
    // console.log('sendHashInputFinalizeFullCmd recv: ', exchangeRet.toString('hex'));
  }
  return {data: resultData, errorCode: ecode};
}

async function sendHashSignCmd(transport, data) {
  const CLA = 0xe0;
  const HASH_SIGN = 0x48;
  const apdu = Buffer.concat([Buffer.from([CLA, HASH_SIGN, 0, 0]),
    Buffer.from([data.length]), data]);
  debugSendLog('sendHashSignCmd send -> ', apdu);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
   exchangeRet.subarray(exchangeRet.length - 2);
  const resultData = (exchangeRet.length <= 2) ? Buffer.alloc(0) :
   exchangeRet.subarray(0, exchangeRet.length - 2);
  if (exchangeRet.length > 2) {
    // mask 0xfe
    resultData[0] = resultData[0] & 0xfe;
  }
  return {
    signature: byteToHexString(resultData),
    errorCode: convertErrorCode(result),
  };
}

async function startUntrustedTransaction(transport, dectx, isContinue,
    amountValueList, inputIndex, targetRedeemScript) {
  let p1 = 0;
  const p2 = (isContinue) ? 0x80 : 0x06;
  const txinHead = 0x03;

  let version = Buffer.alloc(4);
  version = writeUInt32LE(version, dectx.version, 0);
  const inputNum = (inputIndex === -1) ? dectx.vin.length : 1;
  let apdu = Buffer.concat([version, getVarIntBuffer([inputNum])]);
  let errData = await sendHashInputStartCmd(transport, p1, p2, apdu);
  if (errData.errorCode != 0x9000) {
    console.log('fail sendHashInputStartCmd', errData);
    return errData.errorCode;
  }

  p1 = 0x80;
  // p2 = 0x00;
  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    if ((inputIndex !== -1) && (idx !== inputIndex)) {
      continue;
    }
    const header = Buffer.from([txinHead]);
    const txid = reverseBuffer(Buffer.from(dectx.vin[idx].txid, 'hex'));
    let vout = Buffer.alloc(4);
    vout = writeUInt32LE(vout, dectx.vin[idx].vout, 0);
    // if ('issuance' in dectx.vin[idx]) {
    //   vout[3] |= 0x80;
    // }
    let value;
    if ((typeof amountValueList[idx] === 'number') ||
        (typeof amountValueList[idx] === 'bigint')) {
      value = convertValueFromAmount(amountValueList[idx]);
    } else {
      value = Buffer.from(amountValueList[idx], 'hex');
    }
    const script = Buffer.from(targetRedeemScript, 'hex');
    let sequence = Buffer.alloc(4);
    sequence = writeUInt32LE(sequence, dectx.vin[idx].sequence, 0);
    apdu = Buffer.concat([header, txid, vout, value,
      getVarIntBuffer(script.length)]);
    errData = await sendHashInputStartCmd(transport, p1, p2, apdu);
    if (errData.errorCode != 0x9000) {
      console.log('fail sendHashInputStartCmd2', errData);
      break;
    }
    if (script.length !== 0) {
      apdu = Buffer.concat([script, sequence]);
      errData = await sendHashInputStartCmd(transport, p1, p2, apdu);
      if (errData.errorCode != 0x9000) {
        console.log('fail sendHashInputStartCmd2', errData);
        break;
      }
    } else {
      errData = await sendHashInputStartCmd(transport, p1, p2, sequence);
      if (errData.errorCode != 0x9000) {
        console.log('fail sendHashInputStartCmd2', errData);
        break;
      }
    }
  }
  return errData.errorCode;
}

async function liquidFinalizeInputFull(transport, dectx) {
  let apdu = getVarIntBuffer(dectx.vout.length);
  let errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
  if (errData.errorCode != 0x9000) {
    console.log('fail sendHashInputStartCmd2', errData);
    return errData.errorCode;
  }

  let p1 = 0;
  for (let idx = 0; idx < dectx.vout.length; ++idx) {
    const scriptPubkey = Buffer.from(dectx.vout[idx].scriptPubKey.hex, 'hex');
    if ('valuecommitment' in dectx.vout[idx]) {
      let index = Buffer.alloc(4);
      index = writeUInt32BE(index, idx, 0);
      apdu = Buffer.concat([
        // Buffer.from([0xff]),   // signed data flag
        // index,
        Buffer.from(dectx.vout[idx].assetcommitment, 'hex'),
        Buffer.from(dectx.vout[idx].valuecommitment, 'hex')]);
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0,
          Buffer.from(dectx.vout[idx].commitmentnonce, 'hex'));
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
      // errData = await sendHashInputFinalizeFullCmd(
      //     transport, 0, 0, Buffer.from([0])); // confidentialKey
      // if (errData.errorCode != 0x9000) break;
    } else {
      const asset = reverseBuffer(Buffer.from(dectx.vout[idx].asset, 'hex'));
      apdu = Buffer.concat([
        Buffer.from([1]), asset,
        convertValueFromAmount(dectx.vout[idx].value)]);
      errData = await sendHashInputFinalizeFullCmd(transport, 0, 0, apdu);
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
      errData = await sendHashInputFinalizeFullCmd(
          transport, 0, 0, Buffer.from([0])); // nonce
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
      errData = await sendHashInputFinalizeFullCmd(
          transport, 0, 0, Buffer.from([0])); // confidentialKey
      if (errData.errorCode != 0x9000) {
        console.log('liquidFinalizeInputFull ', errData);
        break;
      }
    }
    apdu = Buffer.concat([
      getVarIntBuffer(scriptPubkey.length),
      scriptPubkey]);
    // console.log(`txout(${idx}) = `, apdu.toString('hex'));
    p1 = ((idx + 1) == dectx.vout.length) ? 0x80 : 0x00;
    errData = await sendHashInputFinalizeFullCmd(transport, p1, 0, apdu);
    if (errData.errorCode != 0x9000) {
      console.log(`liquidFinalizeInputFull = `, byteToHexString(errData.data));
      break;
    }
  }
  if (errData.errorCode != 0x9000) {
    console.log('liquidFinalizeInputFull ', errData);
  }
  return errData.errorCode;
}

async function untrustedHashSign(transport, dectx, path, pin, sigHashType) {
  const pathBuffer = parseBip32Path(path).buffer;
  const authorization = Buffer.from(pin, 'hex');

  let locktime = Buffer.alloc(4);
  locktime = writeUInt32BE(locktime, dectx.locktime, 0);

  const apdu = Buffer.concat([
    Buffer.from([pathBuffer.length / 4]),
    pathBuffer,
    Buffer.from([authorization.length]),
    authorization,
    locktime,
    Buffer.from([sigHashType])]);
  // console.log('untrustedHashSign send -> ', apdu.toString('hex'));
  const result = await sendHashSignCmd(transport, apdu);
  if (result.errorCode != 0x9000) {
    console.log('untrustedHashSign fail =', result);
  }
  return result;
}

async function sendProvideIssuanceInformationCmd(
    transport, data, p1) {
  const CLA = 0xe0;
  const LIQUID_PROVIDE_ISSUANCE_INFORMATION = 0xe6;
  const apdu = Buffer.concat(
      [Buffer.from([CLA, LIQUID_PROVIDE_ISSUANCE_INFORMATION, p1, 0]),
        Buffer.from([data.length]), data]);
  debugSendLog('liquidProvideIssuanceInformation send -> ', apdu);
  const exchangeRet = await transport.exchange(apdu);
  const result = (exchangeRet.length <= 2) ? exchangeRet :
    exchangeRet.subarray(exchangeRet.length - 2);
  const ecode = convertErrorCode(result);
  if (ecode !== 0x9000) {
    console.log('sendProvideIssuanceInformationCmd Fail. ecode =', ecode);
  }
  return ecode;
}

async function liquidProvideIssuanceInformation(transport, dectx) {
  let isFind = false;
  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    if ('issuance' in dectx.vin[idx]) {
      isFind = true;
      break;
    }
  }

  let ecode;
  let data;
  if (!isFind) {
    data = Buffer.alloc(dectx.vin.length);
    return await sendProvideIssuanceInformationCmd(transport, data, 0x80);
  }

  for (let idx = 0; idx < dectx.vin.length; ++idx) {
    const p1 = (idx === (dectx.vin.length - 1)) ? 0x80 : 0x00;
    if ('issuance' in dectx.vin[idx]) {
      const issuance = dectx.vin[idx].issuance;
      if ('contractHash' in issuance) {
        data = Buffer.concat([
          reverseBuffer(Buffer.from(issuance.assetBlindingNonce, 'hex')),
          reverseBuffer(Buffer.from(issuance.contractHash, 'hex')),
        ]);
      } else {
        data = Buffer.concat([
          reverseBuffer(Buffer.from(issuance.assetBlindingNonce, 'hex')),
          reverseBuffer(Buffer.from(issuance.assetEntropy, 'hex')),
        ]);
      }
      if ('assetamount' in issuance) {
        data = Buffer.concat([
          data,
          convertValueFromAmount(issuance.assetamount),
        ]);
      } else if ('assetamountcommitment' in issuance) {
        data = Buffer.concat([
          data,
          Buffer.from(issuance.assetamountcommitment, 'hex'),
        ]);
      } else {
        data = Buffer.concat([data, Buffer.alloc(1)]);
      }
      if ('tokenamount' in issuance) {
        data = Buffer.concat([
          data,
          convertValueFromAmount(issuance.tokenamount),
        ]);
      } else if ('tokenamountcommitment' in issuance) {
        data = Buffer.concat([
          data,
          Buffer.from(issuance.tokenamountcommitment, 'hex'),
        ]);
      } else {
        data = Buffer.concat([data, Buffer.alloc(1)]);
      }
      ecode = await sendProvideIssuanceInformationCmd(transport, data, p1);
    } else {
      data = Buffer.alloc(1);
      ecode = await sendProvideIssuanceInformationCmd(transport, data, p1);
    }
    if (ecode !== 0x9000) {
      break;
    }
  }
  return ecode;
}

const disconnectEcode = 0x6d00; // INS_NOT_SUPPORTED

async function checkConnect(transport) {
  // console.time('call getCoinVersion');
  const result = await getCoinVersion(transport);
  // console.timeEnd('call getCoinVersion');
  // console.log('getCoinVersion =', result);
  if (result.errorCode === 0x9000) {
    if ((result.prefixP2pkh === 0x39) &&
        (result.prefixP2sh === 0x27) &&
        (result.coinFamily === 0x01) &&
        (result.coinName === 'Bitcoin') &&
        (result.coinTicker === 'BTC')) {
      // liquid mainnet
    } else if ((result.prefixP2pkh === 0xeb) &&
        (result.prefixP2sh === 0x4b) &&
        (result.coinFamily === 0x01) &&
        (result.coinName === 'Bitcoin') &&
        (result.coinTicker === 'BTC')) {
      // liquid testnet
    } else {
      return disconnectEcode;
    }
  }
  return result.errorCode;
}

function compressPubkey(publicKey) {
  if (!publicKey) return '';
  // return cfdjs.GetCompressedPubkey({pubkey: publicKey}).pubkey;
  const pubkeyArr = Buffer.from(publicKey, 'hex');
  if (pubkeyArr.length === 33) return publicKey;
  const prefix = (pubkeyArr[64] & 1) !== 0 ? 0x03 : 0x02;
  const pubkeySubArr = pubkeyArr.subarray(0, 1 + 32);
  pubkeySubArr[0] = prefix;
  return byteToHexString(pubkeySubArr);
}

const ledgerLiquidWrapper = class LedgerLiquidWrapper {
  constructor(networkType) {
    this.transport = undefined;
    if ((networkType !== 'liquidv1') && (networkType !== 'regtest')) {
      throw new Error('illegal network type.');
    }
    this.networkType = networkType;
    this.mainchainNetwork = (networkType === 'regtest') ?
        'regtest' : 'mainnet';
    this.waitForConnecting = false;
  }

  async getDeviceList() {
    let devList = [];
    let ecode = disconnectEcode;
    let errMsg = 'other error';
    try {
      // devList = await TransportNodeHid.list();
      devList = await TransportWebUSB.list();
      ecode = 0x9000;
      errMsg = '';
    } catch (e) {
      console.log(e);
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: false,
      deviceList: devList,
    };
  }

  async connect(maxWaitTime = undefined, devicePath = undefined) {
    const sleep = (msec) => new Promise(
        (resolve) => setTimeout(resolve, msec));

    if (this.transport) await this.close(this.transport);

    this.waitForConnecting = true;
    const waitLimit = (typeof maxWaitTime === 'number') ? maxWaitTime : 0;
    const path = (typeof devicePath === 'string') ? devicePath : '';
    console.info('connection device:', (!path) ? 'auto' : path);
    let transport = undefined;
    let count = (waitLimit < 1) ? 0 : 1;
    let ecode = disconnectEcode;
    let errMsg = 'other error';
    while ((count <= waitLimit) && this.waitForConnecting) {
      try {
        // transport = await TransportNodeHid.open(path);
        transport = await TransportWebUSB.create();

        ecode = await checkConnect(transport);
        if (ecode === 0x9000) {
          this.transport = transport;
          break;
        } else if (ecode !== disconnectEcode) {
          console.log('illegal error. ', ecode);
          await this.close(transport);
          break;
        }
      } catch (e) {
        // console.log(`connection fail. count=${count}`, e);
        const errText = e.toString();
        if (errText.indexOf('DisconnectedDevice: Cannot write to HID device') >= 0) {
          // disconnect error
        } else if (errText.indexOf('TransportError: NoDevice') >= 0) {
          // device connect error
        } else if (errText.indexOf('cannot open device with path') >= 0) {
          // device connect error
        } else if (errText.indexOf('The device was disconnected') >= 0) {
          // device connect error
        } else if (errText.indexOf('Must be handling a user gesture to show a permission request') >= 0) {
          // device connect error
        } else if (errText.indexOf('No device selected.') >= 0) {
          // disconnect error
        } else {
          console.warn(e);
          console.log(`connection fail.(exception) count=${count}`, e);
          ecode = 0x6000;
          errMsg = errText;
          break;
        }
      }
      if (transport) await this.close(transport);
      transport = undefined;
      console.info(`connection fail. count=${count}`);
      ++count;
      if (count < waitLimit) await sleep(1000);
    }

    if (ecode === 0x9000) {
      errMsg = '';
    } else if (ecode === disconnectEcode) {
      if (this.waitForConnecting) {
        errMsg = 'connection fail.';
      } else {
        errMsg = 'connection cancel.';
      }
    }
    this.waitForConnecting = false;
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: (ecode === disconnectEcode),
    };
  }

  cancelConnect() {
    this.waitForConnecting = false;
  }

  async isConnected() {
    let ecode = disconnectEcode;
    if (this.transport !== undefined) {
      try {
        ecode = await checkConnect(this.transport);
      } catch (e) {
        const errText = e.toString();
        if (errText.indexOf('DisconnectedDevice: Cannot write to HID device') >= 0) {
          // disconnect error
        } else if (errText.indexOf('TransportError: NoDevice') >= 0) {
          // device connect error
        } else if (errText.indexOf('The device was disconnected.') >= 0) {
          // device connect error
        } else if (errText.indexOf('Must be handling a user gesture to show a permission request') >= 0) {
          // device connect error
        } else if (errText.indexOf('No device selected.') >= 0) {
          // disconnect error
        } else {
          console.log(`connection fail.(exception) `, e);
          ecode = 0x8000;
        }
      }
      if (ecode !== 0x9000) this.disconnect();
    }
    let errMsg = 'other error';
    if (ecode === 0x9000) {
      errMsg = '';
    } else if (ecode === disconnectEcode) {
      errMsg = 'connection fail.';
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: (ecode === disconnectEcode),
    };
  }

  async disconnect() {
    if (this.transport !== undefined) {
      await this.close(this.transport);
      this.transport = undefined;
    }
  }

  async close(transport) {
    if (transport !== undefined) {
      await transport.close();
    }
  }

  getPublicKeyRedeemScript(publicKey) {
    const pubkeyArr = Buffer.from(publicKey, 'hex');
    const hash160Buf = hash160(pubkeyArr);
    // OP_DUP OP_HASH160 <20byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    const buf = Buffer.concat([
      Buffer.from([0x76, 0xa9, 0x14]),
      hash160Buf,
      Buffer.from([0x88, 0xac]),
    ]);
    return byteToHexString(buf);
  }

  async getWalletPublicKey(bip32Path) {
    let result = undefined;
    const connRet = await this.isConnected();
    let ecode = connRet.errorCode;
    let errMsg = connRet.errorMessage;
    if (connRet.success) {
      // TODO(k-matsuzawa): notfound liquid option(0x10, 0x11)
      const p2 = 1; // = 0x10;
      // console.time('call getWalletPublicKey');
      result = await getWalletPublicKey(
          this.transport, bip32Path, p2);
      // console.timeEnd('call getWalletPublicKey');
      // console.log('getWalletPublicKey result =', result);
      ecode = result.errorCode;
      errMsg = (ecode === 0x9000) ? '' : 'other error';
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
      publicKey: (!result) ? '' : compressPubkey(result.pubkey),
      chainCode: (!result) ? '' : result.chainCode,
    };
  }

  async getXpubKey(bip32Path) {
    let xpub = undefined;
    const connRet = await this.isConnected();
    let ecode = connRet.errorCode;
    let errMsg = connRet.errorMessage;
    if (connRet.success) {
      const p2 = 1; // = 0x10;
      const parent = await getWalletPublicKey(
          this.transport, bip32Path, p2, true);
      ecode = parent.errorCode;
      if (ecode !== 0x9000) {
        errMsg = 'other error';
      } else {
        const pubkey = await getWalletPublicKey(
            this.transport, bip32Path, p2);
        ecode = parent.errorCode;
        if (ecode !== 0x9000) {
          errMsg = 'other error';
        } else {
          const pathArr = parseBip32Path(bip32Path).array;
          xpub = createExtPubKey(
              this.mainchainNetwork,
              pathArr.length,
              pathArr[pathArr.length - 1],
              pubkey.chainCode,
              compressPubkey(pubkey.pubkey),
              compressPubkey(parent.pubkey));
          //          const extkey = cfdjs.CreateExtkey({
          //            network: this.mainchainNetwork,
          //            extkeyType: 'extPubkey',
          //            parentKey: compressPubkey(parent.pubkey),
          //            key: compressPubkey(pubkey.pubkey),
          //            chainCode: pubkey.chainCode,
          //            depth: pathArr.length,
          //            childNumber: pathArr[pathArr.length - 1],
          //          });
          //          xpub = extkey.extkey;
        }
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
      xpubKey: (!xpub) ? '' : xpub,
    };
  }

  async setupHeadlessAuthorization(authorizationPublicKey) {
    const connRet = await this.isConnected();
    let ecode = connRet.errorCode;
    let errMsg = connRet.errorMessage;
    if (connRet.success) {
      ecode = await liquidSetupHeadless(this.transport,
          authorizationPublicKey);
      errMsg = (ecode === 0x9000) ? '' : 'other error.';
      if (ecode === 0x6985) {
        errMsg = 'CONDITIONS_OF_USE_NOT_SATISFIED';
      }
    }
    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: errMsg,
      disconnect: connRet.disconnect,
    };
  }

  //  interface WalletUtxoData extends UtxoData {
  //    bip32Path: string; // key-1(bip32 path)
  //    txid: string; // key(outpoint)
  //    vout: number; // key(outpoint)
  //    amount?: bigint | number;
  //    valueCommitment?: string;
  //    pubkey?: string; // pubkey.
  //    redeemScript?: string; // redeem script.
  //  }

  decodeRawTransaction(proposalTx) {
    return decodeRawTransaction(proposalTx);
  }

  async getSignature(proposalTransaction,
      walletUtxoList, authorizationSignature) {
    const signatureList = [];
    const connRet = await this.isConnected();
    if (!connRet.success) {
      return {
        success: connRet.success,
        errorCode: connRet.errorCode,
        errorCodeHex: connRet.errorCode.toString(16),
        errorMessage: connRet.errorMessage,
        disconnect: connRet.disconnect,
        signatureList: signatureList,
      };
    }
    //    const dectx = cfdjs.ElementsDecodeRawTransaction({
    //      hex: proposalTransaction, network: this.networkType,
    //      mainchainNetwork: this.mainchainNetwork});
    const dectx = decodeRawTransaction(proposalTransaction);
    // console.log('*** dectx ***\n', JSON.stringify(dectx, null, '  '));

    const amountValueList = [];

    const utxoList = walletUtxoList;
    for (const txin of dectx.vin) {
      let isFind = false;
      for (const utxo of utxoList) {
        if ((txin.txid === utxo.txid) && (txin.vout === utxo.vout)) {
          let value = 0;
          if ('valueCommitment' in utxo) {
            value = utxo.valueCommitment;
          } else if ('amount' in utxo) {
            value = utxo.amount;
          }
          amountValueList.push(value);
          isFind = true;
          break;
        }
      }
      if (!isFind) {
        // throw new Error('txin is not in the utxo list.');
        amountValueList.push(1); // dummy amount
      }
    }
    let ecode = 0x9000;

    const utxoScriptList = [];
    // Collect redeemScript before startUntrustedTransaction
    // because you need to call getWalletPublicKey.
    for (const utxo of walletUtxoList) {
      let targetIndex = -1;
      for (let index = 0; index < dectx.vin.length; ++index) {
        if ((dectx.vin[index].txid === utxo.txid) &&
            (dectx.vin[index].vout === utxo.vout)) {
          targetIndex = index;
          break;
        }
      }
      if (targetIndex === -1) {
        throw new Error('wallet utxo is not in the txin list.');
      }

      let redeemScript = '';
      if (!utxo.descriptor && !utxo.redeemScript) {
        // bip32 path -> pubkey -> lockingscript
      } else if (!utxo.descriptor) {
        redeemScript = utxo.redeemScript;
      } else {
        //        const desc = cfdjs.ParseDescriptor({
        //          isElements: true,
        //          descriptor: utxo.descriptor,
        //          network: this.networkType,
        //        });
        //        if (('scripts' in desc) && (desc.scripts.length > 0) &&
        //            ('redeemScript' in desc.scripts[desc.scripts.length - 1])) {
        //          redeemScript = desc.scripts[desc.scripts.length - 1].redeemScript;
        //        }
      }

      if (!redeemScript) {
        if (!utxo.pubkey) {
          const pubkeyRet = await this.getWalletPublicKey(utxo.bip32Path);
          ecode = pubkeyRet.errorCode;
          if (ecode !== 0x9000) {
            break;
          }
          redeemScript = this.getPublicKeyRedeemScript(pubkeyRet.publicKey);
        } else {
          redeemScript = this.getPublicKeyRedeemScript(utxo.pubkey);
        }
      }
      utxoScriptList.push({
        redeemScript: redeemScript,
        targetIndex: targetIndex,
        utxo: utxo,
      });
    }

    // console.info('amountValueList =', amountValueList);
    if (ecode === 0x9000) {
      ecode = await startUntrustedTransaction(this.transport, dectx, false,
          amountValueList, -1, '');
    }
    if (ecode === 0x9000) {
      ecode = await liquidFinalizeInputFull(this.transport, dectx);
    }
    if (ecode === 0x9000) {
      ecode = await liquidProvideIssuanceInformation(this.transport, dectx);
    }

    if (ecode === 0x9000) {
      // sighashtype: 1=all only
      const sighashtype = 1;
      for (const utxoData of utxoScriptList) {
        ecode = await startUntrustedTransaction(this.transport, dectx,
            true, amountValueList, utxoData.targetIndex,
            utxoData.redeemScript);
        if (ecode !== 0x9000) {
          break;
        }
        const signatureRet = await untrustedHashSign(this.transport, dectx,
            utxoData.utxo.bip32Path, authorizationSignature, sighashtype);
        ecode = signatureRet.errorCode;
        if (ecode !== 0x9000) {
          break;
        }
        signatureList.push({
          utxoData: utxoData.utxo,
          signature: signatureRet.signature,
        });
      }
    }

    return {
      success: (ecode === 0x9000),
      errorCode: ecode,
      errorCodeHex: ecode.toString(16),
      errorMessage: (ecode === 0x9000) ? '' : 'other error.',
      disconnect: false,
      signatureList: signatureList,
    };
  }
};

const networkType = {
  LiquidV1: 'liquidv1',
  Regtest: 'regtest',
};

const addressType = {
  Legacy: 'legacy',
  P2shSegwit: 'p2sh-segwit',
  Bech32: 'bech32',
};

module.exports = ledgerLiquidWrapper;
module.exports.LedgerLiquidWrapper = ledgerLiquidWrapper;
module.exports.NetworkType = networkType;
module.exports.NetworkType.LiquidV1 = networkType.LiquidV1;
module.exports.NetworkType.Regtest = networkType.Regtest;
module.exports.AddressType = addressType;
module.exports.AddressType.Legacy = addressType.Legacy;
module.exports.AddressType.P2shSegwit = addressType.P2shSegwit;
module.exports.AddressType.Bech32 = addressType.Bech32;
