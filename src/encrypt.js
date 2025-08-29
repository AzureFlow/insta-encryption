import crypto from "crypto";
import sealedbox from "tweetnacl-sealedbox-js";

// "#PWD_INSTAGRAM_BROWSER"
export const DEFAULT_PWD_PREFIX = "#PWD_BROWSER";
const DEFAULT_ENCRYPTION_VERSION = 5;

// InstagramPasswordEncryption
// https://www.instagram.com/api/v1/web/data/shared_data/
// https://threads.com/api/v1/web/data/shared_data/
//   encryption → public_key
const ENCRYPTION_KEY_ID = "47";
const ENCRYPTION_PUBLIC_KEY = "896a078ad1a39e5c09e07abe5496dcfe5ea20617513bca853b0baa67fdd3212e";
const ENCRYPTION_VERSION = "10";

const PUBLIC_KEY_HEX_LENGTH = 64;
const FORMAT_VERSION = 1;
const VERSION_FIELD_LENGTH = 1;
const KEY_ID_FIELD_LENGTH = 1;
const ENCRYPTED_KEY_LENGTH_FIELD = 2;
const KEY_LENGTH_BYTES = 32;
const TAG_LENGTH = 16;
const HEADER_LENGTH = VERSION_FIELD_LENGTH + KEY_ID_FIELD_LENGTH + ENCRYPTED_KEY_LENGTH_FIELD + KEY_LENGTH_BYTES + sealedbox.overheadLength + TAG_LENGTH;

/**
 * @param {string} password
 * @param {string} [prefix]
 * @returns {Promise<string>}
 */
export async function encryptPassword(password, prefix = DEFAULT_PWD_PREFIX) {
	const timestamp = Math.floor(Date.now() / 1000).toString();
	return encryptPasswordInternal(parseInt(ENCRYPTION_KEY_ID, 10), ENCRYPTION_PUBLIC_KEY, password, timestamp, parseInt(ENCRYPTION_VERSION, 10), prefix);
}

/**
 * @param {number} encryptionKeyId
 * @param {string} encryptionPublicKey
 * @param {string} password
 * @param {string} timestamp
 * @param {number} [encryptionVersion]
 * @param {string} [prefix]
 * @returns {Promise<string>}
 */
async function encryptPasswordInternal(encryptionKeyId, encryptionPublicKey, password, timestamp, encryptionVersion = DEFAULT_ENCRYPTION_VERSION, prefix = DEFAULT_PWD_PREFIX) {
	const textEncoder = new TextEncoder();
	const passwordArr = textEncoder.encode(password);
	const timestampArr = textEncoder.encode(timestamp);

	const encryptedData = await encrypt(encryptionKeyId, encryptionPublicKey, passwordArr, timestampArr);

	return [prefix, encryptionVersion, timestamp, Buffer.from(encryptedData).toString("base64")].join(":");
}

/**
 * @param {number} encryptionKeyId
 * @param {string} encryptionPublicKeyHex
 * @param {Uint8Array} data
 * @param {Uint8Array} additionalData
 * @returns {Promise<Uint8Array>}
 */
async function encrypt(encryptionKeyId, encryptionPublicKeyHex, data, additionalData) {
	if(encryptionPublicKeyHex.length !== PUBLIC_KEY_HEX_LENGTH) {
		throw new Error("public key is not a valid hex string");
	}

	const decodedPublicKey = Buffer.from(encryptionPublicKeyHex, "hex");
	if(!decodedPublicKey) {
		throw new Error("public key is not a valid hex string");
	}

	const result = new Uint8Array(HEADER_LENGTH + data.length);
	let position = 0;

	result[position] = FORMAT_VERSION;
	position += VERSION_FIELD_LENGTH;

	result[position] = encryptionKeyId;
	position += KEY_ID_FIELD_LENGTH;

	const key = await crypto.subtle.generateKey({
		name: "AES-GCM",
		length: KEY_LENGTH_BYTES * 8,
	}, true, ["encrypt", "decrypt"]);

	const exportedKeyPromise = crypto.subtle.exportKey("raw", key);
	const encryptedPromise = crypto.subtle.encrypt({
		name: "AES-GCM",
		iv: new Uint8Array(12),
		additionalData: additionalData,
		// Meta devs made a typo here.
		// They used "tagLen" instead of "tagLength".
		// I suggest using typechecking.
		// Also, 16 is not a valid length. I assume they meant 128 bits, TAG_LENGTH * 8.
		// tagLen: TAG_LENGTH,
		// tagLength: TAG_LENGTH * 8,
	}, key, data.buffer);

	const [exportedKey, encrypted] = await Promise.all([exportedKeyPromise, encryptedPromise]);

	/** @type {Uint8Array} */
	const sealedData = sealedbox.seal(new Uint8Array(exportedKey), decodedPublicKey);

	result[position] = sealedData.length & 255;
	result[position + 1] = sealedData.length >> 8 & 255;
	position += ENCRYPTED_KEY_LENGTH_FIELD;

	result.set(sealedData, position);
	position += KEY_LENGTH_BYTES;
	position += sealedbox.overheadLength;
	if(sealedData.length !== KEY_LENGTH_BYTES + sealedbox.overheadLength) {
		throw new Error("encrypted key is the wrong length");
	}

	const encryptedUint8Arr = new Uint8Array(encrypted);
	// Extract the authentication tag
	const tagData = encryptedUint8Arr.slice(-TAG_LENGTH);
	// Encrypted data without tag
	const encryptedWithoutTag = encryptedUint8Arr.slice(0, -TAG_LENGTH);

	// Put the tag into the result buffer
	result.set(tagData, position);
	position += TAG_LENGTH;

	// Put the ciphertext into the result buffer after the tag
	result.set(encryptedWithoutTag, position);

	return result;
}
