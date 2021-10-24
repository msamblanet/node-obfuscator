import Crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import extend from 'extend';
import { IConfig, Overrides, BaseConfigurable } from '@msamblanet/node-config-types';

export interface IAlgSettings {
  name: string;
  base?: string;
  notes?: string;
  password: string;
  salt: string;
  iterations: number;
  hash: string;
  alg: string;
  stringEncoding: Crypto.Encoding;
  binEncoding: Crypto.Encoding;
  doNotEncodeAfter?: string; // ISO encoded date - "2030-12-31"
}

export interface IObfuscatorConfig extends IConfig {
  defaultAlg: string;
  algSettings: Record<string, IAlgSettings>;
}

export class Obfuscator extends BaseConfigurable<IObfuscatorConfig> {
  public static DEFAULT_CONFIG: IObfuscatorConfig = {
    defaultAlg: 'DEFAULT',
    algSettings: {
      DEFAULT: {
        name: 'DEFAULT',
        notes: 'This is a default obfuscation password - it should only be used for insensitive data as anybody with source access can decode this - See README.md for recommended production usage',
        password: 'fiQ7YCt7BTQ47aDotBFxpzSfibBjiI5BX21MeMUNugPRC9RQSwjDyWd4abiq0SNwhZbVmASGC6OxrJuS',
        salt: 'zDvGZz2epkEeSbxAeMFxobCfcjG2GAHIcZZ8WX3SfEYX4g2idD3VTQsrCQIC7QsyYE4B36tRKEm1hUib',
        iterations: 100_000,
        hash: 'sha256',
        alg: 'aes-256-cbc',
        stringEncoding: 'utf8',
        binEncoding: 'base64',
        doNotEncodeAfter: undefined,
      }
    }
  };

  public static _isAfterCheckDate(limit?: string): boolean {
    if (!limit) {
      return false;
    }

    const dt = Date.parse(limit);
    if (dt <= Date.now()) {
      return true;
    }

    return false;
  }

  protected readonly cache: Record<string, Buffer> = {};
  protected algSettings: Record<string, IAlgSettings> = {};

  // Create the obfuscator - optionally provide the password (default used if undefined)
  public constructor(...config: Overrides<IObfuscatorConfig>) {
    super(Obfuscator.DEFAULT_CONFIG, ...config);
    this.configure();
  }

  public encodeBuffer(value: Crypto.BinaryLike, alg: string = this.config.defaultAlg): string {
    return this._encode(alg, value);
  }

  public encodeString(value: string, alg: string = this.config.defaultAlg): string {
    return this._encode(alg, Buffer.from(value).toString(this.getSettings(alg)?.stringEncoding));
  }

  public decodeString(value: string): string {
    const rv = this._decode(value);
    return rv.data.toString(rv.settings.stringEncoding);
  }

  public decodeBuffer(value: string): Buffer {
    return this._decode(value).data;
  }

  protected configure(): void {
    let numberWithBase = 0;
    do {
      let numberProcessed = 0;
      numberWithBase = 0;

      for (const alg of Object.getOwnPropertyNames(this.config.algSettings)) {
        const algCfg = this.config.algSettings[alg];

        // Ignore if already processed
        if (this.algSettings[alg]) {
          continue;
        }

        // Don't process if we have not yet processed the base alg
        if (algCfg.base && !this.algSettings[algCfg.base]) {
          if (!this.config.algSettings[algCfg.base]) {
            throw new Error(`Unknown alg: ${algCfg.base}`);
          }

          numberWithBase++;
          continue;
        }

        numberProcessed++;

        // Sanity checks
        if (algCfg.name !== alg) {
          throw new Error(`Name incorrectly set for alg: ${alg}`);
        }

        // Lookup base
        const baseCfg = algCfg.base ? this.algSettings[algCfg.base] : undefined;

        // Extend and add in
        this.algSettings[alg] = extend(true, {}, baseCfg, { password: '' }, algCfg, { base: '' });
      }

      if (numberWithBase && !numberProcessed) {
        throw new Error('Circular dependency in alg config');
      }
    } while (numberWithBase);
  }

  // Generate a key for an alogritm, bypassing the cache
  protected generateKey(settings: IAlgSettings): Buffer {
    if (settings.password.length < 8) {
      throw new Error(`Password is too short: ${settings.name}`);
    }

    const algInfo = Crypto.getCipherInfo(settings.alg);
    /* istanbul ignore next */
    if (!algInfo) throw new Error(`Unknonwn cipher: ${settings.alg}`);
    return Crypto.pbkdf2Sync(settings.password, settings.salt, settings.iterations, algInfo.keyLength, settings.hash);
  }

  // Looks up a key via the cache
  protected getKey(settings: IAlgSettings): Buffer {
    return this.cache[settings.name] ??= this.generateKey(settings); // eslint-disable-line no-return-assign
  }

  protected getSettings(alg: string): IAlgSettings {
    return this.algSettings[alg];
  }

  // Encode with a specified alogrithm (default used if not specified)
  protected _encode(alg: string, value: Crypto.BinaryLike): string {
    const settings = this.getSettings(alg);
    if (!settings) {
      throw new Error(`Unknown alg: ${alg}`);
    }

    if (Obfuscator._isAfterCheckDate(settings.doNotEncodeAfter)) {
      throw new Error(`Alg has expired for encoding: ${alg}`);
    }

    const algInfo = Crypto.getCipherInfo(settings.alg);
    /* istanbul ignore next */
    if (!algInfo) throw new Error(`Unknonwn cipher: ${settings.alg}`);
    /* istanbul ignore next */
    const ivLength = algInfo.ivLength ?? 16;

    const key = this.getKey(settings);
    const iv = Crypto.randomBytes(ivLength);
    const cipher = Crypto.createCipheriv(settings.alg, key, iv);
    const encoded = Buffer.concat([cipher.update(value), cipher.final()]);

    return `${alg}:${iv.toString(settings.binEncoding)}:${encoded.toString(settings.binEncoding)}`;
  }

  // Decode a string created with encode
  protected _decode(value: string): { settings: IAlgSettings; data: Buffer } {
    const parts = value.split(':');
    if (parts.length !== 3) {
      throw new Error('Malformed encoded string');
    }

    const settings = this.getSettings(parts[0]);
    if (!settings) {
      throw new Error(`Unknown alg: ${parts[0]}`);
    }

    const key = this.getKey(settings);
    const iv = Buffer.from(parts[1], settings.binEncoding);

    const decipher = Crypto.createDecipheriv(settings.alg, key, iv);
    const data = Buffer.concat([decipher.update(parts[2], settings.binEncoding), decipher.final()]);

    return {
      settings,
      data
    };
  }
}
export default Obfuscator;
