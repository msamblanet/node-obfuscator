# Node Obfuscator Template

This repository is part of a collection of my personal node.js libraries and templates.  I am making them available to the public - feel free to offer suggestions, report issues, or make PRs via GitHub.

This project is a class for managing the obfuscation of values to prevent accidental viewing.

**Note:** If a sufficiently strong and secure password is used, the values can be considered encrypted.  If you rely on this, take care to ensure you properly secure the password.

Obfuscation is performed by using a password-based key generation and then doing a salted encryption.  The entire result is packed into a string which can be placed in a configuration file.

Alogrithm details are stored in the configuration, allowing the users to customize them if needed.

## Usage

```
// Use the default instance
import obfuscator from "@msamblanet/node-obfuscator";

// Optionally configure the obfuscator
obfuscator.configure({});

const obfuscated = obfuscator.encodeString("Hello world");
const restored = obfuscator.decodeString(obfuscated);

// You can also create your own instances

import { Obfuscator } from "@msamblanet/node-obfuscator";
const obfuscator = new Obfuscator(/* optional config */);
// use obfuscator as above...
```
