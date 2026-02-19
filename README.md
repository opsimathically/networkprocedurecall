# Usage

- Create a new github repo.
- Clone it (gh repo clone opsimathically/reponame)
- Download this as a zip from github.
- Unpack it in your new repo directory (cp -a /path/to/source/. /path/to/destination/)
- npm install
- Unit tests should follow: ./test/your_test_dir/sometest.test.ts
- use 'npm run test' to run all unit tests at once.

# Zod and Runtime Schema Validation

We use ts-to-zod to autogenerate schemas for runtime data validation.

- [ts-to-zod github](https://github.com/fabien0102/ts-to-zod)
- [ts-to-zod npm](https://www.npmjs.com/package/ts-to-zod)

Schemas built examine types AND typedoc within your types file, so the schema can validate via lengths, regular expressions, etc. Please see the ts-to-zod documentation on what typedoc expressions are valid, and how to use them in your types.

Running **_npm run ts-to-zod_** will autogenerate schemas based on the **_ts-to-zod.config.mjs_** file configuration.

When you run **_npm run build_** it automatically runs ts-to-zod beforehand. However, when running unit tests you'll need to rebuild your schemas on your own if they've changed (aka: run **_npm run ts-to-zod_**).

# Project Name

Project description.

## Install

```bash
npm install @opsimathically/yourproject
```

## Building from source

This package is intended to be run via npm, but if you'd like to build from source,
clone this repo, enter directory, and run `npm install` for dev dependencies, then run
`npm run build`.

## Usage

[See API Reference for documentation](https://github.com/opsimathically/yourproject/docs/)

[See unit tests for more direct usage examples](https://github.com/opsimathically/yourproject/test/index.test.ts)
