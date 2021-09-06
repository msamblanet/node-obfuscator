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

export type ObfuscatorConfigOverrides = null | undefined | RecursivePartial<ObfuscatorConfig>;

export class Obfuscator {
    public static DEFAULT_CONFIG: ObfuscatorConfig = {
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

    protected readonly cache: { [key: string]: Buffer } = {}
    protected readonly config: ObfuscatorConfig;

    // Create the obfuscator - optionally provide the password (default used if undefined)
    public constructor(...config: ObfuscatorConfigOverrides[]) {
        this.config = this.configure(...config);
    }

    protected configure(...configOverrides: ObfuscatorConfigOverrides[]): ObfuscatorConfig {
        const newConfig = extend(true, {}, Obfuscator.DEFAULT_CONFIG, ...configOverrides); // Extend with a deep copy

        for (const alg of Object.getOwnPropertyNames(newConfig.algSettings)) {
            const algCfg = newConfig.algSettings[alg];

            // Sanity checks
            if (algCfg.name !== alg) throw new Error(`Name incorrectly set for alg: ${alg}`);

            //
            // Extend does not copy values if their value is undefined.  This means setting a property in an AlgConfig
            // to undefined will result in the base value being used.
            //
            // If done on a password, the base password (which is likely insecure) may be used, creating a security issue.
            //
            // This check looks for this condition and remediates it by setting the password to "",
            // resulting in a password-too-short error instead of accidental encryption with a possibly insecure password
            //
            for (const config of configOverrides) {
                if (Object.prototype.hasOwnProperty?.call(config?.algSettings?.[alg] ?? {}, "password"))
                    algCfg.password = config?.algSettings?.[alg]?.password ?? "";
            }
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

        return newConfig;
    }

    public static _isAfterCheckDate(limit?: string): boolean {
        if (limit == null) return false;

        const dt = Date.parse(limit);
        if (dt <= Date.now()) return true;
        return false;
    }

    // Generate a key for an alogritm, bypassing the cache
    protected generateKey(settings: AlgSettings): Buffer {
        if (settings.password.length < 8) throw new Error(`Password is too short: ${settings.name}`);
        return Crypto.pbkdf2Sync(settings.password, settings.salt, settings.iterations, Crypto.getCipherInfo(settings.alg)?.keyLength as number, settings.hash);
    }

    // Looks up a key via the cache
    protected getKey(settings: AlgSettings): Buffer {
        return this.cache[settings.name] ??= this.generateKey(settings);
    }

    protected getSettings(alg: string): AlgSettings {
        return this.config.algSettings?.[alg];
    }

    // Encode with a specified alogrithm (default used if not specified)
    protected _encode(alg: string, val: Crypto.BinaryLike): string {
        const settings = this.getSettings(alg);
        if (!settings) throw new Error(`Unknown alg: ${alg}`);

        if (Obfuscator._isAfterCheckDate(settings.doNotEncodeAfter)) throw new Error(`Alg has expired for encoding: ${alg}`)

        const key = this.getKey(settings);
        const iv = Crypto.randomBytes(Crypto.getCipherInfo(settings.alg)?.ivLength as number);
        const cipher = Crypto.createCipheriv(settings.alg, key, iv);
        const encoded = Buffer.concat([ cipher.update(val), cipher.final() ]);

        return `${alg}:${iv.toString(settings.binEncoding)}:${encoded.toString(settings.binEncoding)}`;
    }

    public encodeBuffer(val: Crypto.BinaryLike, alg: string = this.config.defaultAlg): string {
        return this._encode(alg, val);
    }

    public encodeString(val: string, alg: string = this.config.defaultAlg): string {
        return this._encode(alg, Buffer.from(val).toString(this.getSettings(alg)?.stringEncoding));
    }

    // Decode a string created with encode
    protected _decode(val: string): { settings: AlgSettings, data: Buffer } {
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

    public decodeString(val: string): string {
        const rv = this._decode(val);
        return rv.data.toString(rv.settings.stringEncoding);
    }

    public decodeBuffer(val: string): Buffer {
        return this._decode(val).data;
    }
}

export default Obfuscator;
