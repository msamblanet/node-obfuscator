import * as dotenv from 'dotenv';
dotenv.config();

import Foo from '../src/index';

test("example test", () => {
    expect(Foo).toEqual("Example export");
})
