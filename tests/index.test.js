const senv = require('../index'),
      envfile = require('envfile'),
      writeFile = require('fs').writeFileSync,
      remove = require('fs').unlinkSync
      exists = require('fs').existsSync;

const TMPDIR = process.env.TMPDIR;

const EXAMPLE_ENV_FILE = `
ENV_VAR=123
ENV_VAR_2=abc
`.trim()

test('encrypts/decrypts string successfully', () => {
    const testString = "Hello world!";
    const testPassword = "password";
    const encryptedString = senv.encryptString(testString, testPassword);

    expect(encryptedString).not.toBe(testString);
    expect(encryptedString).not.toBeNull();

    expect(senv.decryptString(encryptedString, testPassword)).toBe(testString);
});

test('encrypting env file fails without password', () => {
    expect(() => senv.encryptEnvFile('path', undefined)).toThrowError('password');
    expect(() => senv.encryptEnvFile('path', null)).toThrowError('password');
    expect(() => senv.encryptEnvFile('path', '')).toThrowError('password');
});

test('decrypting env file fails without password', () => {
    expect(() => senv.decryptEnvFile('path', undefined)).toThrowError('password');
    expect(() => senv.decryptEnvFile('path', null)).toThrowError('password');
    expect(() => senv.decryptEnvFile('path', '')).toThrowError('password');
});

test('encrypted env file is written successfully', () => {
    const path = `${TMPDIR}.env.test1`;
    const encryptedEnvPath = `${TMPDIR}.env.enc.test1`;

    writeFile(path, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(path, encryptedEnvPath, 'password');

    expect(exists(encryptedEnvPath)).toBeTruthy();

    remove(path);
    remove(encryptedEnvPath)
});

test('encrypted env file has correct variables', () => {
    const path = `${TMPDIR}.env.test1`;
    writeFile(path, EXAMPLE_ENV_FILE);

    const encryptedEnvFile = senv.encryptEnvFile(path, null, 'password');

    expect(encryptedEnvFile).toContain('ENV_VAR');
    expect(encryptedEnvFile).toContain('ENV_VAR_2');

    remove(path);
});


test('encrypted env file variable values have changed', () => {
    const path = `${TMPDIR}.env.test2`;
    writeFile(path, EXAMPLE_ENV_FILE);

    const encryptedEnvFile = senv.encryptEnvFile(path, null, 'password');

    expect(encryptedEnvFile).not.toEqual(EXAMPLE_ENV_FILE);

    remove(path);
});

test('decrypted env file is written successfully', () => {
    const path = `${TMPDIR}.env.test1`;
    const encryptedEnvPath = `${TMPDIR}.env.enc.test1`;

    writeFile(path, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(path, encryptedEnvPath, 'password');
    remove(path);

    senv.decryptEnvFile(encryptedEnvPath, path, 'password');
    expect(exists(path)).toBeTruthy();

    remove(encryptedEnvPath);
});

test('decrypted env file has correct variables', () => {
    const envVarPath = `${TMPDIR}.env.test3`;
    const encryptedEnvVarPath = `${TMPDIR}.env.enc.test3`;
    writeFile(envVarPath, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(envVarPath, encryptedEnvVarPath, 'password');
    const decryptedEnvFile = senv.decryptEnvFile(encryptedEnvVarPath, null, 'password');

    expect(decryptedEnvFile.trim()).toContain('ENV_VAR');
    expect(decryptedEnvFile.trim()).toContain('ENV_VAR_2');

    remove(envVarPath);
    remove(encryptedEnvVarPath);
});

test('decrypted env file variables are correct', () => {
    const envVarPath = `${TMPDIR}.env.test4`;
    const encryptedEnvVarPath = `${TMPDIR}.env.enc.test4`;
    writeFile(envVarPath, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(envVarPath, encryptedEnvVarPath, 'password');
    const decryptedEnvFile = senv.decryptEnvFile(encryptedEnvVarPath, null, 'password');

    expect(decryptedEnvFile.trim()).toEqual(EXAMPLE_ENV_FILE.trim());

    remove(envVarPath);
    remove(encryptedEnvVarPath);
});
