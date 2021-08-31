import Crypto from "crypto";
import extend from "extend";

// https://stackoverflow.com/questions/41980195/recursive-partialt-in-typescript
export type RecursivePartial<T> = {
    [P in keyof T]?: RecursivePartial<T[P]>;
};

export interface AlgSettings {
    name: string
    base?: string
    notes?: string
    password: string
    salt: string
    iterations: number
    hash: string
    alg: string
    stringEncoding: Crypto.Encoding
    binEncoding: Crypto.Encoding,
    doNotEncodeAfter?: string // ISO encoded date - "2030-12-31"
}

export interface ObfuscatorConfig {
    defaultAlg: string,
    algSettings: { [key: string]: AlgSettings }
}

export class Obfuscator {
    static DEFAULT_CONFIG: ObfuscatorConfig = {
        defaultAlg: "DEFAULT",
        algSettings: {
            DEFAULT: {
                name: "DEFAULT",
                notes: "This is a default obfuscation password - it should only be used for insensitive data as anybody with source access can decode this - See README.md for recommended production usage",
                password: "fiQ7YCt7BTQ47aDotBFxpzSfibBjiI5BX21MeMUNugPRC9RQSwjDyWd4abiq0SNwhZbVmASGC6OxrJuS",
                salt: "zDvGZz2epkEeSbxAeMFxobCfcjG2GAHIcZZ8WX3SfEYX4g2idD3VTQsrCQIC7QsyYE4B36tRKEm1hUib",
                iterations: 100000,
                hash: "sha256",
                alg: "aes-256-cbc",
                stringEncoding: "utf8",
                binEncoding: "base64",
                doNotEncodeAfter: undefined,
            }
        }
    }

    _cache: { [key: string]: Buffer } = {}
    _config: ObfuscatorConfig;
    _configLocked = false;

    // Create the obfuscator - optionally provide the password (default used if undefined)
    constructor(config?: RecursivePartial<ObfuscatorConfig>) {
        this._config = this.configure(config);
        this._configLocked = !!config; // Allow one reconfigure if we did not pass a config in...
    }

    configure(config?: RecursivePartial<ObfuscatorConfig>): ObfuscatorConfig {
        if (this._configLocked) throw new Error("Already configured");

        const newConfig = extend(true, {}, Obfuscator.DEFAULT_CONFIG, config); // Extend with a deep copy

        for (const alg of Object.getOwnPropertyNames(newConfig.algSettings)) {
            const algCfg = newConfig.algSettings[alg];

            // Sanity checks
            if (algCfg.name !== alg) throw new Error(`Name incorrectly set for alg: ${alg}`);
        }

        let numWithBase = 0;
        do {
            let numProcessed = 0;
            numWithBase = 0;

            for (const alg of Object.getOwnPropertyNames(newConfig.algSettings)) {
                const algCfg = newConfig.algSettings[alg];
                if (!algCfg.base) continue;

                const baseCfg = newConfig.algSettings[algCfg.base];
                if (!baseCfg) throw new Error(`Unknown alg: ${algCfg.base}`)

                if (!baseCfg.base) {
                    numProcessed++;
                    delete algCfg.base;
                    newConfig.algSettings[alg] = extend(true, {}, baseCfg, algCfg);
                } else {
                    numWithBase++;
                }
            }

            if (numWithBase && !numProcessed) throw new Error("Circular dependency in alg config");
        } while (numWithBase);

        this._configLocked = true;
        this._config = newConfig;
        this._cache = {};

        return newConfig;
    }

    static _isAfterCheckDate(limit?: string, now: number = new Date().getTime()): boolean {
        if (limit == null) return false;

        const dt = Date.parse(limit);
        if (dt <= now) return true;
        return false;
    }

    // Generate a key for an alogritm, bypassing the cache
    generateKey(settings: AlgSettings): Buffer {
        if (settings.password.length < 8) throw new Error(`Password is too short: ${settings.name}`);
        return Crypto.pbkdf2Sync(settings.password, settings.salt, settings.iterations, Crypto.getCipherInfo(settings.alg)?.keyLength as number, settings.hash);
    }

    // Looks up a key via the cache
    getKey(settings: AlgSettings): Buffer {
        return this._cache[settings.name] ??= this.generateKey(settings);
    }

    getSettings(alg: string): AlgSettings {
        return this._config.algSettings?.[alg];
    }

    // Encode with a specified alogrithm (default used if not specified)
    _encode(alg: string, val: Crypto.BinaryLike): string {
        const settings = this.getSettings(alg);
        if (!settings) throw new Error(`Unknown alg: ${alg}`);

        if (Obfuscator._isAfterCheckDate(settings.doNotEncodeAfter)) throw new Error(`Alg has expired for encoding: ${alg}`)

        const key = this.getKey(settings);
        const iv = Crypto.randomBytes(Crypto.getCipherInfo(settings.alg)?.ivLength as number);
        const cipher = Crypto.createCipheriv(settings.alg, key, iv);
        const encoded = Buffer.concat([ cipher.update(val), cipher.final() ]);

        return `${alg}:${iv.toString(settings.binEncoding)}:${encoded.toString(settings.binEncoding)}`;
    }

    encodeBuffer(val: Crypto.BinaryLike, alg: string = this._config.defaultAlg): string {
        return this._encode(alg, val);
    }

    encodeString(val: string, alg: string = this._config.defaultAlg): string {
        return this._encode(alg, Buffer.from(val).toString(this.getSettings(alg)?.stringEncoding));
    }

    // Decode a string created with encode
    _decode(val: string): { settings: AlgSettings, data: Buffer } {
        const parts = val.split(":");
        if (parts.length != 3) throw new Error("Malformed encoded string");

        const settings = this.getSettings(parts[0]);
        if (!settings) throw new Error(`Unknown alg: ${parts[0]}`);

        const key = this.getKey(settings);
        const iv = Buffer.from(parts[1], settings.binEncoding);

        const decipher = Crypto.createDecipheriv(settings.alg, key, iv);
        const data = Buffer.concat([ decipher.update(parts[2], settings.binEncoding), decipher.final() ]);

        return {
            settings,
            data
        };
    }

    decodeString(val: string): string {
        const rv = this._decode(val);
        return rv.data.toString(rv.settings.stringEncoding);
    }

    decodeBuffer(val: string): Buffer {
        return this._decode(val).data;
    }
}

export default new Obfuscator();
