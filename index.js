const crypto = require('crypto'),
      envfile = require('envfile'),
      writeFile = require('fs').writeFileSync,
      readFile = require('fs').readFileSync;
      exists = require('fs').existsSync;

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
    const key = crypto.pbkdf2Sync(password, iv, 10000, 32, 'sha512');

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
    const key = crypto.pbkdf2Sync(password, iv, 10000, 32, 'sha512');

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
 * Gets a password for decryption from various sources in order.
 * @param {string} fileName - The file name to convert
 * @returns {string}  - the corresponding password file name
 */
function getPasswordFromEnvironment(fileName) {
    // Get password for individual .env file from environment variable
    const individualPasswordEnvVarName = fileName
        .replace('.encrypted', '') // ignore encrypted filename part
        .replace('.enc', '') // ignore encrypted filename part
        .replace('.', 'DOT') // replace first . with DOT
        .replace(/\./g, '_') // replace all other . with _
        .concat('_PASS')
        .toUpperCase();

    if (process.env[individualPasswordEnvVarName]) {
        return process.env[individualPasswordEnvVarName];
    }

    // Get password for individual .env file from password file
    const individualPasswordFileName = fileName
        .replace('.encrypted', '') // ignore encrypted filename part
        .replace('.enc', '') // ignore encrypted filename part
        .concat('.pass');

    if(exists(individualPasswordFileName)) {
        return readFile(individualPasswordFileName, 'utf8');
    }

    // Get password for all .env files from environment variable
    const globalPasswordEnvVarName = 'DOTENV_PASS';

    if (process.env[globalPasswordEnvVarName]) {
        return process.env[globalPasswordEnvVarName];
    }

    // Get password for all .env files from file
    const globalPasswordFileName = '.env.pass';

    if (exists(globalPasswordFileName)) {
        return readFile(globalPasswordFileName, 'utf8');
    }

    // if no password found, throw error
    throw new Error(
        'No password provided.'
    );
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
    if(!password) {
        password = getPasswordFromEnvironment(inputFile);
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
    if(!password) {
        password = getPasswordFromEnvironment(inputFile);
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
    getPasswordFromEnvironment,
}