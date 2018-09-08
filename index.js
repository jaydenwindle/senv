const crypto = require('crypto'),
      envfile = require('envfile')
      writeFile = require('fs').writeFileSync;

const ALGORITHM = 'aes-256-cbc';

/**
 * Encrypts a string.
 * @param {string} string - The string to be encrypted.
 * @param {string} password - The password with which to encrypt the string.
 */
function encryptString(string, password) {
    var cipher = crypto.createCipher(ALGORITHM, password)
    var crypted = cipher.update(string, 'utf8', 'hex')
    crypted += cipher.final('hex');
    return crypted;
}

/**
 * Decrypts a string.
 * @param {string} string - The string to be decrypted.
 * @param {string} password - The password with which to decrypt the string.
 */
function decryptString(text, password) {
    var decipher = crypto.createDecipher(ALGORITHM, password)
    var dec = decipher.update(text, 'hex', 'utf8')
    dec += decipher.final('utf8');
    return dec;
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
function encryptEnvFile(inputFile, outputFile, password) {
    if (!password) {
        throw new Error(
            'No password provided.\
            \nProvide a password using the -p flag (see `eenv encrypt --help` for details)'
        );
    }
    const envVariables = envfile.parseFileSync(inputFile);

    for (const variableName in envVariables) {
        if (envVariables.hasOwnProperty(variableName)) {
            const value = envVariables[variableName];
            envVariables[variableName] = encryptString(value, password);
        }
    }

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
function decryptEnvFile(inputFile, outputFile, password) {
    if (!password) {
        throw new Error(
            'No password provided.\
            \nProvide a password using the -p flag (see `eenv decrypt --help` for details)'
        );
    }
    const envVariables = envfile.parseFileSync(inputFile);

    for (const variableName in envVariables) {
        if (envVariables.hasOwnProperty(variableName)) {
            const encryptedValue = envVariables[variableName];
            envVariables[variableName] = decryptString(encryptedValue, password);
        }
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
}