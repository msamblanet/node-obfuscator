# Node Obfuscator
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This repository is part of a collection of my personal node.js libraries and templates.  I am making them available to the public - feel free to offer suggestions, report issues, or make PRs via GitHub.

This project is a class for managing the obfuscation of values to prevent accidental viewing.  If a sufficiently strong and secure password is used, the values can be considered secure.  If you rely on this, take care to ensure you follow best pratices to generate and secure the passwords used.

Obfuscation is performed by using a password-based key generation and then doing a salted encryption.  The entire result is packed into a string which can be placed in a configuration file.

Alogrithm details are stored in the configuration, allowing the users to customize them.

## Usage

```
// Use the default instance
import { Obfuscator } from "@msamblanet/node-obfuscator";
const obfuscator = new Obfuscator(/* optional config */);
// use obfuscator as above...
```

### Recommended Pratice

- Configure a new alogrithm name for each environment, extending from the base alogrithm
    - Append a revision or year to the end of the name so that you can manage future alogrithm updates
- Use an environment variable to set the password for each environment.
    - Take care to ensure these passwords are **NEVER** committed into GIT or shared on insecure channels
    - Developers can use dotenv to set development values for the password
    - Operational systems can configure them via dotenv, configuration files, or local environment variables depending on how you deploy

```
// Simple example showing how to configure a dev and prod alogrithm
require { Obfuscator } from "@msamblanet/node-obfuscator";
const obfuscator = new Obfuscator({
    defaultAlg: (process.NODE_ENV === "production") ? "PROD21" : "DEV21",
    algSettings: {
        DEV21: {
            name: "DEV21",
            base: "DEFAULT",
            password: process.env.DEV_OBF_PW
        }
        PROD21: {
            name: "PROD",
            base: "DEFAULT",
            password: process.env.PROD_OBF_PW
        }
    }
});

const myDatabasePassword = obfuscator.decodeString(myConfig.dbPasswordObfuscated);
```

## API

### default

The default export from the library is the Obfuscator class

### Obfuscator.constructor(config)

Constructs a new obfuscator.  You may optionally provide configuration on this call.

### Obfuscator.encodeString(val, alg): string

Encodes the string ```val``` using algroithm ```alg```.  If ```alg``` is not specified, the default alogrithm is used.

### Obfuscator.encodeBuffer(val, alg): string

Encodes the buffer ```val``` using algroithm ```alg```.  If ```alg``` is not specified, the default alogrithm is used.

### Obfuscator.decodeString(val): string

Decodes the encoded string.  The alogrithm is determined from the encoded string.  The alogrithm used to encode MUST be correctly configured in the Obfuscator's config.

### Obfuscator.decodeBuffer(val): Buffer

Decodes the encoded buffer.  The alogrithm is determined from the encoded string.  The alogrithm used to encode MUST be correctly configured in the Obfuscator's config.

### ObfuscatorConfig

- defaultAlg - The default alogrithm to encode with
- algSettings - A hash of settings for the different alogrithms

### AlgSettings

- name - The name of the alogrithm - must match the key used to store it in the algSettings
- base - The name of an alogrithm to extend - if specified, any unspecified settings are inherited from the base
    - Note that values of ```undefined``` do not override the base.
    - Note that the value of ```password``` is NOT inherited to prevent accidental use of an insecure password.
- notes - Optional string with notes on the alogrithm - not used programatically
- password - Password used to derive the key - if set to a string less than 8 characters, an error will be thrown when trying to use the key
- salt - Salt used to derive the key
- iterations - Number of hash iterations to generate the key
- hash - Hash alogritm used to generate the key
- alg - Name of the cipher (per Node's crypto module)
- stringEncoding - Encoding of the unencoded string when using ```encodeString``` and ```decodeString```
- binEncoding - Encoding to use for the IV and encrypted data (generally base64 or hex)
- doNotEncodeAfter - Optional - If used, set to an ISO date and the code will refuse to encode with this key on the date specified - used to help implement policies regarding the maximum age of a key
