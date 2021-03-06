import Crypto from 'node:crypto';
import LibDefault, * as Lib from '../src/index.js';

const longString = '1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890';
const testBuffer = Crypto.randomBytes(100);
const { defaultAlg } = Lib.Obfuscator.DEFAULT_CONFIG;
const defaultPw = Lib.Obfuscator.DEFAULT_CONFIG.algSettings[defaultAlg].password;

test('Verify Exports', () => {
  expect(Lib.Obfuscator).not.toBeNull();

  expect(LibDefault).not.toBeNull();
  expect(LibDefault).toEqual(Lib.Obfuscator);
});

test('Verify Default Config', () => {
  const t = Lib.Obfuscator.DEFAULT_CONFIG;
  const t2 = t.algSettings[t.defaultAlg];

  // Just some basic sanity checks on the defaults
  expect(t).not.toBeNull();
  expect(t.defaultAlg).not.toBeNull();
  expect(t.algSettings).not.toBeNull();
  expect(t2).not.toBeNull();
  expect(t2.base).toBeUndefined(); // Should not be on default
  expect(t2.name).toEqual(t.defaultAlg);
  expect(t2.password).not.toBeNull();
  expect(t2.salt).not.toBeNull();
  expect(t2.iterations).not.toBeNull();
  expect(t2.alg).not.toBeNull();
  expect(t2.stringEncoding).not.toBeNull();
  expect(t2.binEncoding).not.toBeNull();
  expect(t2.doNotEncodeAfter).toBeUndefined(); // Should not be on default
  // notes is optional but can exist on the default, so do not test
});

test('Verify Default Roundtrip', () => {
  const t = new Lib.Obfuscator();

  // Test with different lengths to ensure no boundary conditions
  for (let i = 0; i < 100; i++) {
    const testString = longString.slice(0, Math.max(0, i));
    expect(t.decodeString(t.encodeString(testString))).toEqual(testString);

    const testBuffer = Crypto.randomBytes(i);
    expect(t.decodeBuffer(t.encodeBuffer(testBuffer))).toEqual(testBuffer);
  }
});

test('Verify unknown alg errors', () => {
  const t = new Lib.Obfuscator();

  expect(() => t.encodeString('foo', 'foo')).toThrowError('Unknown alg: foo');
  expect(() => t.encodeBuffer(testBuffer, 'foo')).toThrowError('Unknown alg: foo');

  expect(() => t.decodeString('foo:xxx:xxx')).toThrowError('Unknown alg: foo');
  expect(() => t.decodeBuffer('foo:xxx:xxx')).toThrowError('Unknown alg: foo');
});

test('Verify format checks', () => {
  const t = new Lib.Obfuscator();

  expect(() => t.decodeString('foo')).toThrowError('Malformed encoded string');
  expect(() => t.decodeBuffer('foo')).toThrowError('Malformed encoded string');

  expect(() => t.decodeString('foo:bar')).toThrowError('Malformed encoded string');
  expect(() => t.decodeBuffer('foo:bar')).toThrowError('Malformed encoded string');

  expect(() => t.decodeString('foo:1:2:3:4:5')).toThrowError('Malformed encoded string');
  expect(() => t.decodeBuffer('foo:1:2:3:4:5')).toThrowError('Malformed encoded string');
});

test('IsAfterDate Check', () => {
  const t = Lib.Obfuscator;

  expect(t._isAfterCheckDate(undefined)).toEqual(false);

  const oldNow = Date.now;
  try {
    let now = 0;
    Date.now = () => now;

    now = Date.parse('2021-01-01');
    expect(t._isAfterCheckDate('2020-01-01')).toEqual(true);
    now = Date.parse('2020-01-02');
    expect(t._isAfterCheckDate('2020-01-01')).toEqual(true);
    now = Date.parse('2020-01-01');
    expect(t._isAfterCheckDate('2020-01-01')).toEqual(true);
    now = Date.parse('2019-12-31');
    expect(t._isAfterCheckDate('2020-01-01')).toEqual(false);
  } finally {
    Date.now = oldNow;
  }
});

test('Config check - bad name', () => {
  expect(() => new Lib.Obfuscator({ algSettings: { foo: { name: 'bar' } } })).toThrowError('Name incorrectly set for alg: foo');
  expect(() => new Lib.Obfuscator({ algSettings: { foo: { name: 'foo', base: 'bar' } } })).toThrowError('Unknown alg: bar');
});

test('Config check - Curcular Dep', () => {
  expect(() => new Lib.Obfuscator({ algSettings: { foo: { name: 'foo', base: 'bar' }, bar: { name: 'bar', base: 'foo' } } })).toThrowError('Circular dependency in alg config');
});

test('Verify base configuration behavior', () => {
  const t = new Lib.Obfuscator({ algSettings: { foo: { name: 'foo', base: defaultAlg, password: defaultPw }, bar: { name: 'bar', base: 'foo', password: 'UnitTests' } } });
  let enc: string;

  enc = t.encodeString(longString, 'foo');
  expect(t.decodeString(enc)).toEqual(longString);
  // Enc should be compatible with DEV - verify that...
  expect(t.decodeString(enc.replace(/^foo:/, `${defaultAlg}:`))).toEqual(longString);

  enc = t.encodeString(longString, 'bar');
  expect(t.decodeString(enc)).toEqual(longString);
  // Enc2 should NOT be compatible with foo or dev - verify that...
  expect(() => t.decodeString(enc.replace(/^bar:/, 'foo:'))).toThrow();
  expect(() => t.decodeString(enc.replace(/^bar:/, `${defaultAlg}:`))).toThrow();

  enc = t.encodeBuffer(testBuffer, 'foo');
  expect(t.decodeBuffer(enc)).toEqual(testBuffer);
  // Enc should be compatible with DEV - verify that...
  expect(t.decodeBuffer(enc.replace(/^foo:/, `${defaultAlg}:`))).toEqual(testBuffer);

  enc = t.encodeBuffer(testBuffer, 'bar');
  expect(t.decodeBuffer(enc)).toEqual(testBuffer);
  // Enc2 should NOT be compatible with foo or dev - verify that...
  expect(() => t.decodeBuffer(enc.replace(/^bar:/, 'foo:'))).toThrow();
  expect(() => t.decodeBuffer(enc.replace(/^bar:/, `${defaultAlg}:`))).toThrow();
});

test('Verify do not encode after', () => {
  const t = new Lib.Obfuscator({ algSettings: { foo: { name: 'foo', base: defaultAlg, doNotEncodeAfter: '1970-12-31' } } });

  expect(() => t.encodeString('foo', 'foo')).toThrowError('Alg has expired for encoding: foo');
  expect(() => t.encodeBuffer(testBuffer, 'foo')).toThrowError('Alg has expired for encoding: foo');
});

test('Verify password too short tests', () => {
  let t = new Lib.Obfuscator({ algSettings: { foo: { name: 'foo', base: defaultAlg, password: '123' } } });
  expect(() => t.encodeString('foo', 'foo')).toThrowError('Password is too short: foo');

  t = new Lib.Obfuscator({ algSettings: { foo: { name: 'foo', base: defaultAlg, password: '' } } });
  expect(() => t.encodeString('foo', 'foo')).toThrowError('Password is too short: foo');

  t = new Lib.Obfuscator({ algSettings: { foo: { name: 'foo', base: defaultAlg, password: undefined } } });
  expect(() => t.encodeString('foo', 'foo')).toThrowError('Password is too short: foo');

  t = new Lib.Obfuscator({ algSettings: { foo: { name: 'foo', base: defaultAlg } } });
  expect(() => t.encodeString('foo', 'foo')).toThrowError('Password is too short: foo');
});
