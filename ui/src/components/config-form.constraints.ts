// Control UI helpers derive native constraints and safe initial values from config schemas.
import { schemaType, type JsonSchema } from "./config-form.shared.ts";

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

const CONFIG_FORM_DECIMAL_NUMBER_RE = /^-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/u;

export function coerceConfigFormNumberString(
  value: string,
  integer: boolean,
): number | undefined | string {
  const trimmed = value.trim();
  if (trimmed === "") {
    return undefined;
  }
  if (!CONFIG_FORM_DECIMAL_NUMBER_RE.test(trimmed)) {
    return value;
  }
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed) || (integer && !Number.isInteger(parsed))) {
    return value;
  }
  return parsed;
}

function decimalPlaces(value: number): number {
  const text = String(value).toLowerCase();
  const [coefficient = "", exponentText] = text.split("e");
  const fractionLength = coefficient.split(".")[1]?.length ?? 0;
  const exponent = Number(exponentText ?? 0);
  return Math.max(0, fractionLength - exponent);
}

function normalizePrecision(value: number, step: number | undefined): number {
  if (!step) {
    return value;
  }
  const places = decimalPlaces(step);
  return places <= 100 ? Number(value.toFixed(places)) : value;
}

type DecimalRational = {
  numerator: bigint;
  denominator: bigint;
};

function decimalRational(value: number): DecimalRational {
  const [coefficientText = "", exponentText] = String(value).toLowerCase().split("e");
  const negative = coefficientText.startsWith("-");
  const coefficient = negative ? coefficientText.slice(1) : coefficientText;
  const [whole = "0", fraction = ""] = coefficient.split(".");
  const exponent = Number(exponentText ?? 0);
  const digits = BigInt(`${whole}${fraction}`);
  const decimalPlaces = fraction.length - exponent;
  const numerator = decimalPlaces < 0 ? digits * 10n ** BigInt(-decimalPlaces) : digits;
  return {
    numerator: negative ? -numerator : numerator,
    denominator: decimalPlaces > 0 ? 10n ** BigInt(decimalPlaces) : 1n,
  };
}

export function isNumericMultiple(value: number, multipleOf: number): boolean {
  if (!Number.isFinite(value) || !Number.isFinite(multipleOf) || multipleOf <= 0) {
    return false;
  }
  const valueRational = decimalRational(value);
  const multipleRational = decimalRational(multipleOf);
  const dividend = valueRational.numerator * multipleRational.denominator;
  const divisor = valueRational.denominator * multipleRational.numerator;
  return divisor !== 0n && dividend % divisor === 0n;
}

function jsonValuesEqual(left: unknown, right: unknown, depth = 0): boolean {
  if (left === right) {
    return true;
  }
  if (depth >= 32 || !left || !right || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((entry, index) => jsonValuesEqual(entry, right[index], depth + 1))
    );
  }
  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const keys = Object.keys(leftRecord);
  return (
    keys.length === Object.keys(rightRecord).length &&
    keys.every(
      (key) =>
        Object.hasOwn(rightRecord, key) &&
        jsonValuesEqual(leftRecord[key], rightRecord[key], depth + 1),
    )
  );
}

function matchesJsonSchemaType(type: string, value: unknown): boolean {
  switch (type) {
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    case "array":
      return Array.isArray(value);
    case "object":
      return Boolean(value) && typeof value === "object" && !Array.isArray(value);
    default:
      return false;
  }
}

export function isSupportedConfigValueValid(
  schema: JsonSchema,
  value: unknown,
  depth = 0,
): boolean {
  if (depth >= 32) {
    return false;
  }
  if (
    (schema.allOf &&
      !schema.allOf.every((entry) => isSupportedConfigValueValid(entry, value, depth + 1))) ||
    (schema.anyOf &&
      !schema.anyOf.some((entry) => isSupportedConfigValueValid(entry, value, depth + 1))) ||
    (schema.oneOf &&
      schema.oneOf.filter((entry) => isSupportedConfigValueValid(entry, value, depth + 1))
        .length !== 1)
  ) {
    return false;
  }
  if (schema.const !== undefined && !jsonValuesEqual(schema.const, value)) {
    return false;
  }
  if (schema.enum && !schema.enum.some((entry) => jsonValuesEqual(entry, value))) {
    return false;
  }
  const declaredTypes =
    typeof schema.type === "string" ? [schema.type] : Array.isArray(schema.type) ? schema.type : [];
  if (
    declaredTypes.length > 0 &&
    !declaredTypes.some((type) => matchesJsonSchemaType(type, value))
  ) {
    return false;
  }
  if (typeof value === "string") {
    const length = Array.from(value).length;
    if (
      (schema.minLength !== undefined && length < schema.minLength) ||
      (schema.maxLength !== undefined && length > schema.maxLength)
    ) {
      return false;
    }
    if (schema.pattern) {
      try {
        if (!new RegExp(schema.pattern, "u").test(value)) {
          return false;
        }
      } catch {
        return false;
      }
    }
    return true;
  }
  if (typeof value === "number") {
    return (
      Number.isFinite(value) &&
      (schema.minimum === undefined || value >= schema.minimum) &&
      (schema.maximum === undefined || value <= schema.maximum) &&
      (schema.exclusiveMinimum === undefined || value > schema.exclusiveMinimum) &&
      (schema.exclusiveMaximum === undefined || value < schema.exclusiveMaximum) &&
      (schema.multipleOf === undefined || isNumericMultiple(value, schema.multipleOf))
    );
  }
  if (Array.isArray(value)) {
    if (
      (schema.minItems !== undefined && value.length < schema.minItems) ||
      (schema.maxItems !== undefined && value.length > schema.maxItems)
    ) {
      return false;
    }
    const items = schema.items;
    if (!Array.isArray(items)) {
      return items
        ? value.every((item) => isSupportedConfigValueValid(items, item, depth + 1))
        : true;
    }
    return value.every((item, index) => {
      const itemSchema = items[index];
      if (itemSchema) {
        return isSupportedConfigValueValid(itemSchema, item, depth + 1);
      }
      return schema.additionalItems && typeof schema.additionalItems === "object"
        ? isSupportedConfigValueValid(schema.additionalItems, item, depth + 1)
        : schema.additionalItems !== false;
    });
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    if ((schema.required ?? []).some((key) => !Object.hasOwn(record, key))) {
      return false;
    }
    return Object.entries(record).every(([key, entryValue]) => {
      const propertySchema = schema.properties?.[key];
      if (propertySchema) {
        return isSupportedConfigValueValid(propertySchema, entryValue, depth + 1);
      }
      return schema.additionalProperties && typeof schema.additionalProperties === "object"
        ? isSupportedConfigValueValid(schema.additionalProperties, entryValue, depth + 1)
        : schema.additionalProperties !== false;
    });
  }
  switch (typeof value) {
    case "boolean":
      return true;
    default:
      return value === null;
  }
}

function greatestCommonDivisor(left: bigint, right: bigint): bigint {
  let a = left < 0n ? -left : left;
  let b = right < 0n ? -right : right;
  while (b !== 0n) {
    const remainder = a % b;
    a = b;
    b = remainder;
  }
  return a;
}

function integerCompatibleStep(multipleOf: number): number {
  const [coefficient = "", exponentText] = String(multipleOf).toLowerCase().split("e");
  const [whole = "0", fraction = ""] = coefficient.split(".");
  const exponent = Number(exponentText ?? 0);
  const digits = BigInt(`${whole}${fraction}`);
  const denominatorExponent = fraction.length - exponent;
  const numerator = denominatorExponent < 0 ? digits * 10n ** BigInt(-denominatorExponent) : digits;
  const denominator = denominatorExponent > 0 ? 10n ** BigInt(denominatorExponent) : 1n;
  const divisor = greatestCommonDivisor(numerator, denominator);
  const step = Number(numerator / divisor);
  if (!Number.isFinite(step) || step <= 0) {
    return 1;
  }
  return step;
}

function alignToStep(value: number, step: number, direction: "ceil" | "floor" | "round"): number {
  const valueRational = decimalRational(value);
  const stepRational = decimalRational(step);
  const dividend = valueRational.numerator * stepRational.denominator;
  const divisor = valueRational.denominator * stepRational.numerator;
  const truncated = dividend / divisor;
  const remainder = dividend % divisor;
  const floor = remainder < 0n ? truncated - 1n : truncated;
  const aligned =
    direction === "floor"
      ? floor
      : direction === "ceil"
        ? remainder === 0n
          ? truncated
          : remainder > 0n
            ? truncated + 1n
            : truncated
        : (dividend - floor * divisor) * 2n < divisor
          ? floor
          : floor + 1n;
  return normalizePrecision(Number(aligned) * step, step);
}

type NumericInputConstraints = {
  min?: number;
  max?: number;
  exclusiveMin?: number;
  exclusiveMax?: number;
  step: number | "any";
};

export function numericInputConstraints(schema: JsonSchema): NumericInputConstraints {
  const type = schemaType(schema);
  const multipleOf = finiteNumber(schema.multipleOf);
  const numericStep =
    type === "integer"
      ? multipleOf && multipleOf > 0
        ? integerCompatibleStep(multipleOf)
        : 1
      : multipleOf && multipleOf > 0
        ? multipleOf
        : undefined;
  const rawMinimum = finiteNumber(schema.minimum);
  const rawMaximum = finiteNumber(schema.maximum);
  const exclusiveMinimum = finiteNumber(schema.exclusiveMinimum);
  const exclusiveMaximum = finiteNumber(schema.exclusiveMaximum);

  let min = rawMinimum ?? exclusiveMinimum;
  let max = rawMaximum ?? exclusiveMaximum;
  if (numericStep) {
    if (min !== undefined) {
      min = alignToStep(min, numericStep, "ceil");
    }
    if (max !== undefined) {
      max = alignToStep(max, numericStep, "floor");
    }
    if (exclusiveMinimum !== undefined) {
      const aligned = alignToStep(exclusiveMinimum, numericStep, "ceil");
      const exclusiveAligned =
        aligned <= exclusiveMinimum
          ? normalizePrecision(aligned + numericStep, numericStep)
          : aligned;
      min = min === undefined ? exclusiveAligned : Math.max(min, exclusiveAligned);
    }
    if (exclusiveMaximum !== undefined) {
      const aligned = alignToStep(exclusiveMaximum, numericStep, "floor");
      const exclusiveAligned =
        aligned >= exclusiveMaximum
          ? normalizePrecision(aligned - numericStep, numericStep)
          : aligned;
      max = max === undefined ? exclusiveAligned : Math.min(max, exclusiveAligned);
    }
  }

  return {
    min,
    max,
    exclusiveMin: exclusiveMinimum,
    exclusiveMax: exclusiveMaximum,
    step: numericStep ?? "any",
  };
}

function nextRepresentable(value: number, direction: 1 | -1): number {
  if (!Number.isFinite(value)) {
    return value;
  }
  if (value === 0) {
    return direction > 0 ? Number.MIN_VALUE : -Number.MIN_VALUE;
  }
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setFloat64(0, value);
  const bits = view.getBigUint64(0);
  const nextBits = value > 0 === direction > 0 ? bits + 1n : bits - 1n;
  view.setBigUint64(0, nextBits);
  return view.getFloat64(0);
}

function nextUsableNumber(value: number, direction: 1 | -1, opposite?: number): number {
  if (opposite !== undefined && Number.isFinite(opposite)) {
    const midpoint = value + (opposite - value) / 2;
    if ((direction > 0 && midpoint > value) || (direction < 0 && midpoint < value)) {
      return midpoint;
    }
  }
  const offset = Math.max(1, Math.abs(value));
  const candidate = value + direction * offset;
  if (Number.isFinite(candidate) && candidate !== value) {
    return candidate;
  }
  return nextRepresentable(value, direction);
}

export function normalizeNumericValue(value: number, schema: JsonSchema): number {
  const constraints = numericInputConstraints(schema);
  let normalized = value;
  if (typeof constraints.step === "number") {
    normalized = alignToStep(normalized, constraints.step, "round");
  }
  if (constraints.min !== undefined) {
    normalized = Math.max(constraints.min, normalized);
  }
  if (constraints.max !== undefined) {
    normalized = Math.min(constraints.max, normalized);
  }
  if (constraints.exclusiveMin !== undefined && normalized <= constraints.exclusiveMin) {
    normalized =
      typeof constraints.step === "number"
        ? nextRepresentable(constraints.exclusiveMin, 1)
        : nextUsableNumber(constraints.exclusiveMin, 1, constraints.max);
  }
  if (constraints.exclusiveMax !== undefined && normalized >= constraints.exclusiveMax) {
    normalized =
      typeof constraints.step === "number"
        ? nextRepresentable(constraints.exclusiveMax, -1)
        : nextUsableNumber(constraints.exclusiveMax, -1, constraints.min);
  }
  return normalizePrecision(
    normalized,
    typeof constraints.step === "number" ? constraints.step : undefined,
  );
}

export const NO_SAFE_DEFAULT = Symbol("no-safe-config-default");

type SafeDefault = unknown | typeof NO_SAFE_DEFAULT;

const MAX_AUTO_STRING_DEFAULT_LENGTH = 4096;

function defaultStringValue(schema: JsonSchema): string | typeof NO_SAFE_DEFAULT {
  const minLength = Math.max(0, schema.minLength ?? 0);
  const maxLength = schema.maxLength ?? Math.max(minLength, 0);
  if (
    !Number.isSafeInteger(minLength) ||
    minLength > MAX_AUTO_STRING_DEFAULT_LENGTH ||
    maxLength < minLength
  ) {
    return NO_SAFE_DEFAULT;
  }
  if (schema.pattern) {
    try {
      return minLength === 0 && new RegExp(schema.pattern, "u").test("") ? "" : NO_SAFE_DEFAULT;
    } catch {
      return NO_SAFE_DEFAULT;
    }
  }
  if (minLength === 0) {
    return "";
  }
  return "x".repeat(minLength).slice(0, maxLength);
}

function validatedDefaultCandidate(schema: JsonSchema, candidate: SafeDefault): SafeDefault {
  return candidate !== NO_SAFE_DEFAULT && isSupportedConfigValueValid(schema, candidate)
    ? candidate
    : NO_SAFE_DEFAULT;
}

export function defaultValue(schema?: JsonSchema, depth = 0): SafeDefault {
  if (!schema) {
    return "";
  }
  if (schema.default !== undefined) {
    return validatedDefaultCandidate(schema, schema.default);
  }
  if (schema.const !== undefined) {
    return validatedDefaultCandidate(schema, schema.const);
  }
  if (schema.enum && schema.enum.length > 0) {
    for (const candidate of schema.enum) {
      const validated = validatedDefaultCandidate(schema, candidate);
      if (validated !== NO_SAFE_DEFAULT) {
        return validated;
      }
    }
    return NO_SAFE_DEFAULT;
  }
  if (depth >= 32) {
    return NO_SAFE_DEFAULT;
  }
  const type = schemaType(schema);
  switch (type) {
    case "object": {
      const value: Record<string, unknown> = {};
      for (const key of schema.required ?? []) {
        const propertySchema = schema.properties?.[key];
        if (!propertySchema) {
          return NO_SAFE_DEFAULT;
        }
        const propertyDefault = defaultValue(propertySchema, depth + 1);
        if (propertyDefault === NO_SAFE_DEFAULT) {
          return NO_SAFE_DEFAULT;
        }
        value[key] = propertyDefault;
      }
      return validatedDefaultCandidate(schema, value);
    }
    case "array": {
      const itemCount = Math.max(0, schema.minItems ?? 0);
      if (itemCount === 0) {
        return validatedDefaultCandidate(schema, []);
      }
      if (Array.isArray(schema.items)) {
        const value: unknown[] = [];
        for (let index = 0; index < itemCount; index += 1) {
          const itemSchema =
            schema.items[index] ??
            (schema.additionalItems && typeof schema.additionalItems === "object"
              ? schema.additionalItems
              : undefined);
          if (!itemSchema) {
            return NO_SAFE_DEFAULT;
          }
          const itemDefault = defaultValue(itemSchema, depth + 1);
          if (itemDefault === NO_SAFE_DEFAULT) {
            return NO_SAFE_DEFAULT;
          }
          value.push(itemDefault);
        }
        return validatedDefaultCandidate(schema, value);
      }
      const itemsSchema = schema.items;
      if (!itemsSchema) {
        return NO_SAFE_DEFAULT;
      }
      const itemDefault = defaultValue(itemsSchema, depth + 1);
      return validatedDefaultCandidate(
        schema,
        itemDefault === NO_SAFE_DEFAULT
          ? NO_SAFE_DEFAULT
          : Array.from({ length: itemCount }, () => itemDefault),
      );
    }
    case "boolean":
      return validatedDefaultCandidate(schema, false);
    case "number":
    case "integer": {
      const value = normalizeNumericValue(0, schema);
      return validatedDefaultCandidate(schema, value);
    }
    case "string":
      return validatedDefaultCandidate(schema, defaultStringValue(schema));
    case "null":
      return validatedDefaultCandidate(schema, null);
    default:
      return validatedDefaultCandidate(schema, "");
  }
}
