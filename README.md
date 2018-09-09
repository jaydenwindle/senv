# 🔐 senv

[![Build Status](https://travis-ci.org/jaydenwindle/senv.svg?branch=master)](https://travis-ci.org/jaydenwindle/senv)


A simple CLI tool for encrypting and decrypting .env files.


## Features:
- 🔒 Encrypt and decrypt `.env` files so they can be securely tracked in Git
- 👀 .env file changes are apparent during code review
- 🔢 Supports multiple `.env` files for different environment configurations
- 🎮 Supports encryption and decryption via CLI tool
- 🚢 Easy to configure for use with a CI system


## Installation:

`$ yarn global add senv`

or

`$ npm install -g senv`


## Basic Usage

#### Setup your encryption key
```
$ echo "your_password_here" >> .env.pass
```

#### Encrypt a plain text .env file:
```
$ senv encrypt .env -o .env.enc
```

#### Decrypt an encrypted .env file:
```
$ senv decrypt .env.enc -o .env
```


## Passwords

There are several ways to store your passwords, depending on what works best with
your project's existing setup.

#### One password for all `.env` files
To configure `senv` to use a single password for all `.env` files you have two options.

1) Set the `DOTENV_PASS` environment variable in your `~/.bash_profile`:
```
$ export DOTENV_PASS=your_password_here
```

2) Create a file named `.env.pass` in the same directory as your `.env` file:
```
$ echo "your_password_here" >> .env.pass
```

#### One password for each `.env` file
`senv` will look for and use an environment variables or password file for each `.env` file based
on the filename that is passed in, like so:

```
$ senv encrypt .env                 # Looks for $DOTENV_PASS or .env.pass
$ senv encrypt .env.prod            # Looks for $DOTENV_PROD_PASS or .env.prod.pass

$ senv decrypt .env.prod.enc        # Looks for $DOTENV_PROD_PASS or .env.prod.pass
$ senv decrypt .env.prod.encrypted  # Looks for $DOTENV_PROD_PASS or .env.prod.pass
$ senv decrypt .env.prod.suffix     # Looks for $DOTENV_PROD_SUFFIX_PASS or .env.prod.suffix.pass
```

#### CLI Argument (insecure)
You can also pass in your password as a command line argument, like so:
```
$ senv encrypt .env -p your_password_here
```

However, this method is insecure and should not be your first choice.

## Advanced Usage

#### Update encrypted .env file on each commit:
```
$ echo "#!/bin/sh" >> .git/hooks/pre-commit
$ echo "senv encrypt .env -o .env.enc" >> .git/hooks/pre-commit
$ chmod +x .git/hooks/pre-commit
```

#### Decrypt .env.env file in CI pipeline:
- Add `$DOTENV_PASS` or individual file environment variable via UI

## Why?

Everyone knows it's bad practice to store plaintext secrets in git. Often the alternatives are unecessarily complex for small projects (e.g. Hashicorp Vault), or are a pain to manage (e.g. passing around `.env` files among developers via slack or email 🤮).

This tool makes it easy to encrypt and decrypt any `.env` files so they can be securely tracked in Git.

There are several other great libraries that support encryption of environment variables ([encrypt-env](https://www.npmjs.com/package/encrypt-env), [secure-env](https://www.npmjs.com/package/secure-env), etc), but none fit our use case well (managing secrets in `.env` files with `react-native-config`) for one reason or another.

So I created this tool. Hope it helps someone else out 😊.