import {encryptPassword} from "./encrypt.js";

const password = "password123";

// Instagram
const keyData = await fetchKey("instagram");
console.log("keyData:", keyData);
const encryptedPassword = await encryptPassword(password, keyData.keyId, keyData.publicKey, keyData.version, "#PWD_INSTAGRAM_BROWSER");

// Threads
// const keyData = await fetchKey("threads");
// console.log("keyData:", keyData);
// const encryptedPassword = await encryptPassword(password, keyData.keyId, keyData.publicKey, keyData.version);

console.log(encryptedPassword);


/**
 * @param {"instagram"|"threads"|"facebook"} site
 * @returns {Promise<{keyId: string, publicKey: string, version: string}>}
 */
async function fetchKey(site = "instagram") {
	let url;
	if(site === "instagram") {
		url = "https://www.instagram.com/api/v1/web/data/shared_data/";
	}
	else if(site === "threads") {
		url = "https://threads.com/api/v1/web/data/shared_data/";
	}
	else if(site === "facebook") {
		throw new Error("Unsupported site");
	}
	else {
		throw new Error("Invalid site");
	}

	const sharedDataResp = await fetch(url, {
		headers: {
			"sec-fetch-site": "none",
			"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
		},
	});

	if(!sharedDataResp.ok) {
		throw new Error(`Failed to fetch Instagram shared data (${sharedDataResp.status}): ${await sharedDataResp.text()}`);
	}

	/** @type {{encryption: {key_id: string, public_key: string, version: string}}} */
	const sharedDataContent = await sharedDataResp.json();
	const {key_id: keyId, public_key: publicKey, version} = sharedDataContent.encryption;

	return {
		keyId,
		publicKey,
		version,
	};
}