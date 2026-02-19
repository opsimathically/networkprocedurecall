/**
 * ts-to-zod configuration.  Add elements to the exported default array below to extend
 * this configuration across multiple files.
 *
 * @type {import("ts-to-zod").TsToZodConfig}
 */
export default [
  {
    name: 'zod-to-ts',
    input: './src/types/custom_zod_types/custom_zod_types.d.ts',
    output:
      './src/zod_type_validators/custom_ts_to_zod_generated_validators.ts',
    // this is where we define how types are converted into schemas.  We just take the type name
    // and append _zods to identify that it's a schema not a type.
    getSchemaName: (id) => id + '_zods'
  }
];
