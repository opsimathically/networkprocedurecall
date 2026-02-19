import globals from 'globals';
import pluginJs from '@eslint/js';
import tseslint from 'typescript-eslint';

/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    ignores: [
      'dist/**',
      'node_modules/**',
      'eslint.config.mjs',
      'ts-to-zod.config.mjs'
    ]
  },
  { files: ['**/*.{js,mjs,cjs,ts}'] },
  {
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: true
      },
      globals: { ...globals.browser, ...globals.node }
    }
  },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/consistent-type-exports': 'error',
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports' }
      ],
      '@typescript-eslint/no-this-alias': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      'no-debugger': 'off',
      'no-empty': 'off'
    }
  }
];
