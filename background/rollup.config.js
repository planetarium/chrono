import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";
import json from "@rollup/plugin-json"

export default {
  input: "src/main.ts",
  output: {
    dir: '../build/background',
    format: 'iife'
  },
  plugins: [nodeResolve({
    browser: true,
    preferBuiltins: false,
  }),
  typescript(),
  json(),
  commonjs({ include: /node_modules/ })]
};
