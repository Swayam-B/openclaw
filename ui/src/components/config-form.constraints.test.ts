// @vitest-environment node
import { describe, expect, it } from "vitest";
import {
  coerceConfigFormNumberString,
  defaultValue,
  isNumericMultiple,
  NO_SAFE_DEFAULT,
  normalizeNumericValue,
  numericInputConstraints,
} from "./config-form.constraints.ts";

describe("config form schema constraints", () => {
  it("coerces only decimal and scientific config number spellings", () => {
    expect(coerceConfigFormNumberString("42.5", false)).toBe(42.5);
    expect(coerceConfigFormNumberString(".5e2", false)).toBe(50);
    expect(coerceConfigFormNumberString("-2.5E-3", false)).toBe(-0.0025);
    expect(coerceConfigFormNumberString("1e5", true)).toBe(100_000);
    expect(coerceConfigFormNumberString("", false)).toBeUndefined();

    for (const spelling of [
      "0x10",
      "0b1010",
      "0o17",
      "+5",
      "1_000",
      "Infinity",
      "NaN",
      "1e",
      "e5",
    ]) {
      expect(coerceConfigFormNumberString(spelling, false)).toBe(spelling);
    }
    expect(coerceConfigFormNumberString("42.5", true)).toBe("42.5");
  });

  it("aligns native numeric bounds to JSON Schema multiples", () => {
    const schema = {
      type: "integer",
      minimum: 1,
      maximum: 9,
      multipleOf: 2,
    };
    expect(numericInputConstraints(schema)).toMatchObject({ min: 2, max: 8, step: 2 });
    expect(normalizeNumericValue(9, schema)).toBe(8);
    expect(defaultValue(schema)).toBe(2);
  });

  it("does not let large-number tolerance cross a whole step", () => {
    const schema = {
      type: "number",
      minimum: 10_000_000_000_000_000,
      multipleOf: 3,
    };
    expect(numericInputConstraints(schema).min).toBe(10_000_000_000_000_002);
    expect(defaultValue(schema)).toBe(10_000_000_000_000_002);
    expect(isNumericMultiple(10_000_000_000_000_000, 3)).toBe(false);
    expect(isNumericMultiple(10_000_000_000_000_002, 3)).toBe(true);

    const decimalSchema = {
      type: "number",
      minimum: 10_000_000_000_000_002,
      multipleOf: 10,
    };
    expect(numericInputConstraints(decimalSchema).min).toBe(10_000_000_000_000_010);
    expect(defaultValue(decimalSchema)).toBe(10_000_000_000_000_010);
    expect(isNumericMultiple(10_000_000_000_000_002, 10)).toBe(false);
    expect(isNumericMultiple(0.3, 0.1)).toBe(true);
    expect(isNumericMultiple(0.2 + 0.1, 0.1)).toBe(false);
    expect(
      numericInputConstraints({ type: "number", minimum: -10, maximum: -10, multipleOf: 3 }),
    ).toMatchObject({ min: -9, max: -12 });
    expect(defaultValue({ type: "number", minimum: -10, maximum: -10, multipleOf: 3 })).toBe(
      NO_SAFE_DEFAULT,
    );
  });

  it("converts exclusive integer bounds into reachable native bounds", () => {
    const schema = {
      type: "integer",
      exclusiveMinimum: 2,
      exclusiveMaximum: 8,
    };
    expect(numericInputConstraints(schema)).toMatchObject({
      min: 3,
      max: 7,
      exclusiveMin: 2,
      exclusiveMax: 8,
      step: 1,
    });
  });

  it("preserves decimal step precision", () => {
    const schema = {
      type: "number",
      minimum: 0.1,
      maximum: 0.3,
      multipleOf: 0.1,
    };
    expect(normalizeNumericValue(0.2 + 0.1, schema)).toBe(0.3);
    expect(
      normalizeNumericValue(3 * 1.5e-7, {
        type: "number",
        maximum: 6e-7,
        multipleOf: 1.5e-7,
      }),
    ).toBe(4.5e-7);
  });

  it("derives integer-compatible steps from fractional multiples", () => {
    expect(numericInputConstraints({ type: "integer", multipleOf: 0.5 }).step).toBe(1);
    expect(numericInputConstraints({ type: "integer", multipleOf: 2.5 }).step).toBe(5);
    expect(normalizeNumericValue(3, { type: "integer", multipleOf: 2.5 })).toBe(5);
  });

  it("derives valid defaults for exclusive unconstrained bounds", () => {
    const schema = {
      type: "number",
      exclusiveMinimum: 0,
    };
    expect(numericInputConstraints(schema)).toMatchObject({
      min: 0,
      exclusiveMin: 0,
      step: "any",
    });
    expect(defaultValue(schema)).toBe(1);
  });

  it("derives only defaults that the schema can prove", () => {
    expect(
      defaultValue({
        type: "object",
        required: ["mode", "weights"],
        properties: {
          mode: { type: "string", enum: ["safe", "fast"] },
          weights: {
            type: "array",
            minItems: 2,
            items: { type: "integer", minimum: 2 },
          },
        },
      }),
    ).toEqual({ mode: "safe", weights: [2, 2] });
    expect(defaultValue({ type: "string", minLength: 3 })).toBe("xxx");
    expect(defaultValue({ type: "string", minLength: 3, pattern: "^[0-9]+$" })).toBe(
      NO_SAFE_DEFAULT,
    );
    expect(defaultValue({ type: "string", enum: ["x", ""], pattern: "^$" })).toBe("");
    expect(defaultValue({ type: "integer", enum: [1, 4], minimum: 2, multipleOf: 2 })).toBe(4);
    expect(defaultValue({ type: "string", enum: ["x"], pattern: "^$" })).toBe(NO_SAFE_DEFAULT);
    expect(defaultValue({ type: "null" })).toBeNull();
    expect(defaultValue({ type: "string", allOf: [{ minLength: 3 }] })).toBe(NO_SAFE_DEFAULT);
    expect(defaultValue({ type: "integer", default: 3, multipleOf: 2 })).toBe(NO_SAFE_DEFAULT);
    expect(defaultValue({ type: "string", minLength: 1_000_000_000 })).toBe(NO_SAFE_DEFAULT);
    expect(
      defaultValue({
        type: "array",
        minItems: 3,
        items: [{ type: "string" }, { type: "integer", minimum: 2 }],
        additionalItems: { type: "boolean" },
      }),
    ).toEqual(["", 2, false]);
    expect(
      defaultValue({
        type: "array",
        minItems: 3,
        items: [{ type: "string" }, { type: "integer" }],
        additionalItems: false,
      }),
    ).toBe(NO_SAFE_DEFAULT);
  });
});
