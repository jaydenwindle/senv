const crypto = require('crypto'),
      envfile = require('envfile'),
      writeFile = require('fs').writeFileSync;

const ENCRYPTION_ALGORITHM = 'aes-256-ctr';
const HMAC_ALGORITHM = 'sha256';
const AUTHENTICATION_KEY = 'SENV_AUTHENTICATION';

/**
 * Encrypts a string.
 * @param {string} string - The string to be encrypted.
 * @param {string} password - The password with which to encrypt the string.
 * @param {string} iv - The IV with which to encrypt the string.
 */
async function encryptString(string, password, iv) {
    const key = crypto.scryptSync(password, iv, 32);

    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
    let encrypted = cipher.update(string, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return encrypted;
}

/**
 * Decrypts a string.
 * @param {string} string - The string to be decrypted.
 * @param {string} password - The password with which to decrypt the string.
 * @param {string} iv - The IV with which to encrypt the string.
 */
async function decryptString(string, password, iv) {
    const key = crypto.scryptSync(password, iv, 32);

    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
    let decrypted = decipher.update(string, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

/**
 * Creates an HMAC from a string and password.
 * @param {string} string - The string to with which to create the HMAC.
 * @param {string} password - The password with which to create the HMAC.
 * 
 * @returns {string}  - The created HMAC.
 */
function createHmac(string, password) {
    hmac = crypto.createHmac(HMAC_ALGORITHM, password);
    hmac.update(string);
    return hmac.digest('hex');
}

/**
 * Encrypts a .env file and writes it to disk.
 * @param {string} inputFile    - File path to plain text .env file to encrypt.
 * @param {string} outputFile   - File path to write encrypted .env file to.
 * @param {string} password     - The password with which to encrypt the .env file.
 * 
 * @return {string}            - If outputFile is undefined, encrypted .env contents will be
 *                               returned as a string. Otherwise returns success message.
 */
async function encryptEnvFile(inputFile, outputFile, password) {
    if (!password) {
        throw new Error(
            'No password provided.'
        );
    }
    const envVariables = envfile.parseFileSync(inputFile);

    const hmac = createHmac(JSON.stringify(envVariables), password);
    const iv = hmac.slice(0, 16);

    for (const variableName in envVariables) {
        if (envVariables.hasOwnProperty(variableName)) {
            const value = envVariables[variableName];
            envVariables[variableName] = await encryptString(value, password, iv);
        }
    }

    envVariables[AUTHENTICATION_KEY] = hmac;

    const encryptedEnvVariables = envfile.stringifySync(envVariables);

    if (outputFile) {
        writeFile(outputFile, encryptedEnvVariables);
        return `Encrypted file successfully written to ${outputFile}`
    } else {
        return encryptedEnvVariables;
    }
}

/**
 * Decrypts a .env file and writes it to disk.
 * @param {string} inputFile    - Path to encrypted .env file to decrypt.
 * @param {string} outputFile   - Path to write decrypted .env file to.
 * @param {string} password     - The password with which to decrypt the .env file.
 * 
 * @return {string}            - If outputFile is undefined, encrypted .env contents will be
 *                               returned as a string. Otherwise returns success message.
 */
async function decryptEnvFile(inputFile, outputFile, password) {
    if (!password) {
        throw new Error(
            'No password provided.'
        );
    }
    const envVariables = envfile.parseFileSync(inputFile);
    const hmac = envVariables[AUTHENTICATION_KEY];
    const iv = hmac.slice(0, 16);

    delete envVariables[AUTHENTICATION_KEY];

    for (const variableName in envVariables) {
        if (envVariables.hasOwnProperty(variableName)) {
            const encryptedValue = envVariables[variableName];
            envVariables[variableName] = await decryptString(encryptedValue, password, iv);
        }
    }

    const calculatedHmac = createHmac(JSON.stringify(envVariables), password);

    if (hmac !== calculatedHmac) {
        throw new Error('Incorrect password provided.');
    }

    const decryptedEnvVariables = envfile.stringifySync(envVariables);

    if (outputFile) {
        writeFile(outputFile, decryptedEnvVariables);
        return `Decrypted file successfully written to ${outputFile}`
    } else {
        return decryptedEnvVariables;
    }
}

module.exports = {
    encryptEnvFile,
    decryptEnvFile,
    encryptString,
    decryptString,
}