import {encryptPassword} from "./encrypt.js";

const password = "password123";

// Instagram
const encryptedPassword = await encryptPassword(password, "#PWD_INSTAGRAM_BROWSER");

// Threads
// const encryptedPassword = await encryptPassword(password)

console.log(encryptedPassword);
