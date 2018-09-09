# 🔐 senv

A simple CLI tool for encrypting and decrypting .env files.


## Features:
- 🔒 Encrypt and decrypt `.env` files so they can be securely tracked in Git
- 👀 .env file changes are apparent during code review
- 🔢 Supports multiple `.env` files for different environment configurations
- 🎮 Supports encryption and decryption via CLI tool
- 🚢 Easy to configure for use with a CI system


## Basic Usage

#### Installation:

`$ yarn global add senv`

or

`$ npm install -g senv`

#### Encrypt a plain text .env file:

`$ senv encrypt .env -o .env.enc -p password`

#### Decrypt an encrypted .env file:

`$ senv decrypt .env.enc -o .env -p password`


## Advanced Usage

#### Update encrypted .env file on each commit:
```
$ echo "#!/bin/sh" >> .git/hooks/pre-commit
$ echo "senv encrypt .env -o .env.enc -p password" >> .git/hooks/pre-commit
$ chmod +x .git/hooks/pre-commit
```

#### Decrypt .env.env file in CI pipeline:
- Add `$SENV_PASSWORD` environment variable via UI
- Add the following line to your CI script:

`senv decrypt .env.enc -o .env -p $SENV_PASSWORD`


## Why?

Everyone knows it's bad practice to store plaintext secrets in git. Often the alternatives are unecessarily complex for small projects (e.g. Hashicorp Vault), or are a pain to manage (e.g. passing around `.env` files among developers via slack or email 🤮).

This tool makes it easy to encrypt and decrypt any `.env` files so they can be securely tracked in Git.

There are several other great libraries that support encryption of environment variables ([encrypt-env](https://www.npmjs.com/package/encrypt-env), [secure-env](https://www.npmjs.com/package/secure-env), etc), but none fit our use case well (managing secrets in `.env` files with `react-native-config`) for one reason or another.

So I created this tool. Hope it helps someone else out 😊.