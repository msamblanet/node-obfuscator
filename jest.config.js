// https://jestjs.io/docs/configuration
// https://github.com/kulshekhar/ts-jest
// https://www.nerd.vision/post/testing-a-typescript-project-with-jest-ts-jest
module.exports = {
    testRegex: "/test/.*\.test\.(?:js|ts|mjs)",
    preset: "ts-jest",
    testEnvironment: "node",
    collectCoverage: true,
    collectCoverageFrom: ['src/**/*.{ts,js,mjs}'],
    coverageDirectory: "coverage",
    coverageThreshold: {
        global: {
            branches: 100,
            functions: 100,
            lines: 100,
            statements: 100,
        },
    },
    verbose: true,
    testPathIgnorePatterns: ["/node_modules/", "<rootDir>/dist/"]
};
