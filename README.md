# Node Obfuscator Template

This repository is part of a collection of my personal node.js libraries and templates.  I am making them available to the public - feel free to offer suggestions, report issues, or make PRs via GitHub.

This project is a class for managing the obfuscation of values to prevent accidental viewing.  If a sufficiently strong and secure password is used, the values can be considered secure.  If you rely on this, take care to ensure you follow best pratices to generate and secure the passwords used.

Obfuscation is performed by using a password-based key generation and then doing a salted encryption.  The entire result is packed into a string which can be placed in a configuration file.

Alogrithm details are stored in the configuration, allowing the users to customize them.

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
            password: process.env.DEV_OBF_PW ?? ""
        }
        PROD21: {
            name: "PROD",
            base: "DEFAULT",
            password: process.env.PROD_OBF_PW ?? ""
        }
    }
});

const myDatabasePassword = obfuscator.decodeString(myConfig.dbPasswordObfuscated);
```

## API

### default

The default export from the library is a singleton instance of the Obfuscator

### Obfuscator.constructor(config)

Constructs a new obfuscator.  You may optionally provide configuration on this call.

The obfuscator may only be configured once - either by passing a ```config``` into the constructor or calling ```configure```.

### Obfuscator.configure(config)

Appends the provided configuration data the the object's configuration.

The obfuscator may only be configured once - either by passing a ```config``` into the constructor or calling ```configure```.

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
    - Note that values of ```undefined``` do not override the base.  As a result, we recommend using the nullish operator in the following pattern when adding passwords:
        - ```config.algSettings.PROD21.password ??= "";```
        - Using this pattern will ensure the password is too short (causing it to fail if accidentally used) instead of inheriting it from the base if the value is not specified
- notes - Optional string with notes on the alogrithm - not used programatically
- password - Password used to derive the key - if set to a string less than 8 characters, an error will be thrown when trying to use the key
- salt - Salt used to derive the key
- iterations - Number of hash iterations to generate the key
- hash - Hash alogritm used to generate the key
- alg - Name of the cipher (per Node's crypto module)
- stringEncoding - Encoding of the unencoded string when using ```encodeString``` and ```decodeString```
- binEncoding - Encoding to use for the IV and encrypted data (generally base64 or hex)
- doNotEncodeAfter - Optional - If used, set to an ISO date and the code will refuse to encode with this key on the date specified - used to help implement policies regarding the maximum age of a key
