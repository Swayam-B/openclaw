// Control UI renderers for scalar config form nodes.
import { formatInternationalPhoneNumberForDisplay } from "@openclaw/normalization-core/phone-presentation";
import { html, nothing, type TemplateResult } from "lit";
import { ref } from "lit/directives/ref.js";
import { i18n, t } from "../i18n/index.ts";
import { formatUnknownText } from "../lib/format.ts";
import {
  isNumericMultiple,
  normalizeNumericValue,
  numericInputConstraints,
} from "./config-form.constraints.ts";
import {
  getSensitiveRenderState,
  isSecretRefObject,
  jsonValue,
  renderFieldRow,
  renderSensitiveToggleButton,
  wrapSensitiveControl,
  type ConfigNodeRenderParams,
} from "./config-form.node.shared.ts";
import { resolveConfigFieldMeta as resolveFieldMeta } from "./config-form.search.ts";
import {
  configFieldId,
  hintForPath,
  redactedPlaceholder,
  schemaType,
} from "./config-form.shared.ts";

const scalarInputState = new WeakMap<
  HTMLInputElement,
  { controlIdentity: unknown; sourceIdentity: unknown; pathKey: string }
>();

function setControlValidity(target: HTMLInputElement, message: string): boolean {
  target.setCustomValidity(message);
  target.setAttribute("aria-invalid", String(Boolean(message)));
  return !message;
}

function syncScalarInputIdentity(
  element: Element | undefined,
  controlIdentity: unknown,
  sourceIdentity: unknown,
  pathKey: string,
  renderedValue: string,
  revalidate: (target: HTMLInputElement) => void,
): void {
  if (!(element instanceof HTMLInputElement)) {
    return;
  }
  const previous = scalarInputState.get(element);
  if (previous) {
    const repeatedRowChanged =
      Array.isArray(previous.controlIdentity) &&
      Array.isArray(controlIdentity) &&
      previous.controlIdentity.length !== controlIdentity.length;
    if (
      !Object.is(previous.sourceIdentity, sourceIdentity) ||
      previous.pathKey !== pathKey ||
      repeatedRowChanged
    ) {
      element.value = renderedValue;
      setControlValidity(element, "");
    } else if (!Object.is(previous.controlIdentity, controlIdentity)) {
      revalidate(element);
    }
  }
  scalarInputState.set(element, { controlIdentity, sourceIdentity, pathKey });
}

function stringConstraintMessage(value: string, schema: ConfigNodeRenderParams["schema"]): string {
  const length = Array.from(value).length;
  if (schema.minLength !== undefined && length < schema.minLength) {
    return t("configForm.invalidString");
  }
  if (schema.maxLength !== undefined && length > schema.maxLength) {
    return t("configForm.invalidString");
  }
  if (schema.pattern) {
    try {
      if (!new RegExp(schema.pattern, "u").test(value)) {
        return t("configForm.invalidString");
      }
    } catch {
      return t("configForm.invalidString");
    }
  }
  return "";
}

function shouldClearOptionalEmpty(
  value: string,
  schema: ConfigNodeRenderParams["schema"],
  isRequired: boolean,
): boolean {
  return value === "" && !isRequired && Boolean(stringConstraintMessage(value, schema));
}

function numericConstraintMessage(value: number, schema: ConfigNodeRenderParams["schema"]): string {
  if (!Number.isFinite(value)) {
    return t("configForm.invalidNumber");
  }
  if (schemaType(schema) === "integer" && !Number.isInteger(value)) {
    return t("configForm.invalidNumber");
  }
  if (schema.minimum !== undefined && value < schema.minimum) {
    return t("configForm.invalidNumber");
  }
  if (schema.maximum !== undefined && value > schema.maximum) {
    return t("configForm.invalidNumber");
  }
  if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) {
    return t("configForm.invalidNumber");
  }
  if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) {
    return t("configForm.invalidNumber");
  }
  if (schema.multipleOf !== undefined && schema.multipleOf > 0) {
    if (!isNumericMultiple(value, schema.multipleOf)) {
      return t("configForm.invalidNumber");
    }
  }
  return "";
}

export function renderTextInput(
  params: ConfigNodeRenderParams & { inputType: "text" | "number" },
): TemplateResult {
  const { schema, value, path, hints, disabled, onPatch, inputType } = params;
  const showLabel = params.showLabel ?? true;
  const hint = hintForPath(path, hints);
  const { label, help, tags } = resolveFieldMeta(path, schema, hints);
  const helpId = showLabel && help ? configFieldId(path, "description") : undefined;
  const sensitiveState = getSensitiveRenderState({
    path,
    value,
    hints,
    revealSensitive: params.revealSensitive ?? false,
    isSensitivePathRevealed: params.isSensitivePathRevealed,
  });
  const isStructuredValue =
    value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value);
  const isStructuredSecretRef = isSecretRefObject(value);
  const rawAvailable = params.rawAvailable ?? true;
  const effectiveRedacted = sensitiveState.isRedacted || isStructuredSecretRef;
  const placeholder = effectiveRedacted
    ? isStructuredSecretRef
      ? rawAvailable
        ? t("configForm.structuredSecretRaw")
        : t("configForm.structuredSecretFile")
      : redactedPlaceholder()
    : (hint?.placeholder ??
      (schema.default !== undefined
        ? t("configForm.defaultValue", { value: formatUnknownText(schema.default) })
        : ""));
  const displayValue = effectiveRedacted
    ? ""
    : isStructuredValue
      ? jsonValue(value)
      : (value ?? "");
  const effectiveInputType = sensitiveState.isSensitive && !effectiveRedacted ? "text" : inputType;
  const isPhonePresentation = hint?.presentation === "phone-number";
  const phonePresentation =
    isPhonePresentation && !effectiveRedacted && typeof value === "string"
      ? formatInternationalPhoneNumberForDisplay(value, i18n.getLocale())
      : undefined;
  const controlIdentity = params.controlIdentity ?? params.sourceIdentity ?? value;
  const sourceIdentity = params.sourceIdentity ?? value;
  const controlPathKey = configFieldId(path, "scalar-identity");
  const renderedValue = formatUnknownText(displayValue);
  const revalidate = (target: HTMLInputElement) => {
    if (effectiveRedacted) {
      setControlValidity(target, "");
      return;
    }
    if (inputType === "number") {
      const raw = target.value;
      setControlValidity(
        target,
        raw.trim() === ""
          ? params.isRequired
            ? t("configForm.invalidNumber")
            : ""
          : numericConstraintMessage(Number(raw), schema),
      );
      return;
    }
    const raw = target.value;
    const optionalEmpty = shouldClearOptionalEmpty(raw, schema, params.isRequired);
    setControlValidity(target, optionalEmpty ? "" : stringConstraintMessage(raw, schema));
  };

  const inputControl = html`
    <input
      ${ref((element) =>
        syncScalarInputIdentity(
          element,
          controlIdentity,
          sourceIdentity,
          controlPathKey,
          renderedValue,
          revalidate,
        ),
      )}
      type=${effectiveInputType}
      class="settings-input${effectiveRedacted ? " cfg-redacted" : ""}"
      aria-label=${label}
      aria-describedby=${helpId ?? nothing}
      aria-invalid="false"
      placeholder=${placeholder}
      .value=${renderedValue}
      ?disabled=${disabled}
      ?readonly=${effectiveRedacted}
      @click=${() => {
        if (sensitiveState.isRedacted && !isStructuredSecretRef && params.onToggleSensitivePath) {
          params.onToggleSensitivePath(path);
        }
      }}
      @input=${(event: Event) => {
        if (effectiveRedacted) {
          return;
        }
        const target = event.target as HTMLInputElement;
        const raw = target.value;
        if (inputType === "number") {
          if (raw.trim() === "") {
            if (params.isRequired) {
              setControlValidity(target, t("configForm.invalidNumber"));
            } else {
              setControlValidity(target, "");
              onPatch(path, undefined);
            }
            return;
          }
          const parsed = Number(raw);
          if (setControlValidity(target, numericConstraintMessage(parsed, schema))) {
            onPatch(path, Number.isNaN(parsed) ? raw : parsed);
          }
          return;
        }
        if (shouldClearOptionalEmpty(raw, schema, params.isRequired)) {
          setControlValidity(target, "");
          onPatch(path, undefined);
        } else if (setControlValidity(target, stringConstraintMessage(raw, schema))) {
          onPatch(path, raw);
        }
      }}
      @change=${(event: Event) => {
        if (inputType === "number" || effectiveRedacted) {
          return;
        }
        const target = event.target as HTMLInputElement;
        const raw = target.value;
        const normalized = raw.trim();
        if (shouldClearOptionalEmpty(normalized, schema, params.isRequired)) {
          target.value = normalized;
          setControlValidity(target, "");
          onPatch(path, undefined);
          return;
        }
        const normalizedMessage = stringConstraintMessage(normalized, schema);
        if (normalizedMessage) {
          setControlValidity(target, stringConstraintMessage(raw, schema));
          return;
        }
        target.value = normalized;
        setControlValidity(target, "");
        onPatch(path, normalized);
      }}
    />
  `;
  const revealToggle = isStructuredSecretRef
    ? nothing
    : renderSensitiveToggleButton({
        path,
        state: sensitiveState,
        disabled,
        onToggleSensitivePath: params.onToggleSensitivePath,
      });
  const wrappedInput = wrapSensitiveControl(inputControl, revealToggle);
  const presentedInput = isPhonePresentation
    ? html`
        <span class="settings-phone-presentation">
          ${wrappedInput}
          ${phonePresentation
            ? html`<span class="settings-phone-presentation__value">${phonePresentation}</span>`
            : nothing}
        </span>
      `
    : wrappedInput;
  const control = html`
    ${presentedInput}
    ${schema.default !== undefined
      ? html`
          <openclaw-tooltip .content=${t("configForm.resetToDefault")}>
            <button
              type="button"
              class="btn btn--icon"
              style="width:28px;height:28px;padding:0;"
              aria-label=${t("configForm.resetToDefault")}
              ?disabled=${disabled || effectiveRedacted}
              @click=${() => onPatch(path, schema.default)}
            >
              ↺
            </button>
          </openclaw-tooltip>
        `
      : nothing}
  `;

  return renderFieldRow({ label, help, helpId, tags, showLabel, control });
}

export function renderNumberInput(params: ConfigNodeRenderParams): TemplateResult {
  const { schema, value, path, hints, disabled, onPatch } = params;
  const showLabel = params.showLabel ?? true;
  const { label, help, tags } = resolveFieldMeta(path, schema, hints);
  const helpId = showLabel && help ? configFieldId(path, "description") : undefined;
  const displayValue = value ?? schema.default ?? "";
  const constraints = numericInputConstraints(schema);
  const numericStep = typeof constraints.step === "number" ? constraints.step : 1;
  const controlIdentity = params.controlIdentity ?? params.sourceIdentity ?? value;
  const sourceIdentity = params.sourceIdentity ?? value;
  const controlPathKey = configFieldId(path, "scalar-identity");
  const renderedValue = formatUnknownText(displayValue);
  const revalidate = (target: HTMLInputElement) => {
    const raw = target.value;
    setControlValidity(
      target,
      raw === ""
        ? params.isRequired
          ? t("configForm.invalidNumber")
          : ""
        : numericConstraintMessage(Number(raw), schema),
    );
  };

  // Touch devices and some browsers hide native number spinners; keep explicit
  // adjust buttons so schema-sized edits stay possible without typing.
  const step = (direction: -1 | 1) => {
    if (disabled) {
      return;
    }
    const current = Number(displayValue);
    const base = Number.isFinite(current) ? current : normalizeNumericValue(0, schema);
    onPatch(path, normalizeNumericValue(base + direction * numericStep, schema));
  };
  const control = html`
    <button
      type="button"
      class="btn btn--sm btn--icon"
      aria-label=${`${label}: -${numericStep}`}
      ?disabled=${disabled}
      @click=${() => step(-1)}
    >
      −
    </button>
    <input
      ${ref((element) =>
        syncScalarInputIdentity(
          element,
          controlIdentity,
          sourceIdentity,
          controlPathKey,
          renderedValue,
          revalidate,
        ),
      )}
      type="number"
      class="settings-input"
      aria-label=${label}
      aria-describedby=${helpId ?? nothing}
      aria-invalid="false"
      min=${constraints.min ?? nothing}
      max=${constraints.max ?? nothing}
      step=${constraints.step}
      .value=${renderedValue}
      ?disabled=${disabled}
      @input=${(event: Event) => {
        const target = event.target as HTMLInputElement;
        const raw = target.value;
        if (raw === "") {
          if (params.isRequired) {
            setControlValidity(target, t("configForm.invalidNumber"));
          } else {
            setControlValidity(target, "");
            onPatch(path, undefined);
          }
          return;
        }
        const parsed = raw === "" ? undefined : Number(raw);
        if (
          parsed !== undefined &&
          setControlValidity(target, numericConstraintMessage(parsed, schema))
        ) {
          onPatch(path, parsed);
        }
      }}
      @change=${(event: Event) => {
        const target = event.target as HTMLInputElement;
        if (target.value === "") {
          return;
        }
        const normalized = normalizeNumericValue(Number(target.value), schema);
        target.value = formatUnknownText(normalized);
        setControlValidity(target, "");
        onPatch(path, normalized);
      }}
    />
    <button
      type="button"
      class="btn btn--sm btn--icon"
      aria-label=${`${label}: +${numericStep}`}
      ?disabled=${disabled}
      @click=${() => step(1)}
    >
      +
    </button>
  `;

  return renderFieldRow({ label, help, helpId, tags, showLabel, control });
}

export function renderSelect(
  params: ConfigNodeRenderParams & { options: unknown[] },
): TemplateResult {
  const { schema, value, path, hints, disabled, options, onPatch } = params;
  const showLabel = params.showLabel ?? true;
  const { label, help, tags } = resolveFieldMeta(path, schema, hints);
  const helpId = showLabel && help ? configFieldId(path, "description") : undefined;
  const resolvedValue = value ?? schema.default;
  const currentIndex = options.findIndex(
    (option) => option === resolvedValue || String(option) === String(resolvedValue),
  );
  const unset = "__unset__";

  const control = html`
    <select
      class="settings-select"
      aria-label=${label}
      aria-describedby=${helpId ?? nothing}
      ?disabled=${disabled}
      .value=${currentIndex >= 0 ? String(currentIndex) : unset}
      @change=${(event: Event) => {
        const selectedValue = (event.target as HTMLSelectElement).value;
        onPatch(path, selectedValue === unset ? undefined : options[Number(selectedValue)]);
      }}
    >
      <option value=${unset} ?selected=${currentIndex < 0}>${t("configForm.select")}</option>
      ${options.map(
        (option, index) => html`
          <option value=${String(index)} ?selected=${index === currentIndex}>
            ${String(option)}
          </option>
        `,
      )}
    </select>
  `;

  return renderFieldRow({ label, help, helpId, tags, showLabel, control });
}
