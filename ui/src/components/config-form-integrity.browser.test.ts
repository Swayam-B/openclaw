// Control UI tests cover config form constraints, draft recovery, and repeated controls.
import { render } from "lit";
import { describe, expect, it, vi } from "vitest";
import {
  ConfigFormCollectionDraft,
  type ConfigFormCollectionDraftCommit,
} from "./config-form-collection-draft.ts";
import { configFieldId } from "./config-form.shared.ts";
import { analyzeConfigSchema, renderConfigForm } from "./config-form.ts";

function expectElement<T extends Element>(element: T | null | undefined, label: string): T {
  expect(element instanceof Element, label).toBe(true);
  if (!(element instanceof Element)) {
    throw new Error(`missing ${label}`);
  }
  return element;
}

describe("config form integrity", () => {
  it("applies schema constraints and derives bounded repeated defaults", async () => {
    const onPatch = vi.fn();
    const container = document.createElement("div");
    document.body.append(container);
    const analysis = analyzeConfigSchema({
      type: "object",
      properties: {
        laboratory: {
          type: "object",
          required: ["endpoint", "retryBudget"],
          properties: {
            endpoint: {
              type: "string",
              description: "Lowercase slug.",
              minLength: 3,
              maxLength: 16,
              pattern: "[a-z-]+",
            },
            optionalAlias: {
              type: "string",
              minLength: 3,
            },
            explicitEmpty: {
              type: "string",
              minLength: 0,
              pattern: "^$",
            },
            glyph: {
              type: "string",
              maxLength: 1,
              pattern: "^.$",
            },
            codes: {
              type: "array",
              items: {
                type: "string",
                minLength: 3,
                pattern: "^[0-9]+$",
              },
            },
            limited: {
              type: "array",
              maxItems: 1,
              items: { type: "integer" },
            },
            provider: {
              type: "string",
              description: "Execution provider.",
              enum: ["a", "b", "c", "d", "e", "f"],
            },
            apiKey: { type: "string" },
            retryBudget: {
              type: "integer",
              description: "Even values from two through eight.",
              minimum: 2,
              maximum: 8,
              multipleOf: 2,
            },
            weights: {
              type: "array",
              items: { type: "integer", minimum: 2, maximum: 8, multipleOf: 2 },
            },
          },
        },
      },
    });
    render(
      renderConfigForm({
        schema: analysis.schema,
        uiHints: { "laboratory.apiKey": { sensitive: true } },
        unsupportedPaths: analysis.unsupportedPaths,
        value: {
          laboratory: {
            endpoint: "local-api",
            optionalAlias: "main",
            explicitEmpty: "present",
            glyph: "a",
            codes: [],
            limited: [1],
            provider: "a",
            apiKey: "test-secret",
            retryBudget: 8,
            weights: [2],
          },
        },
        showAdvanced: true,
        onShowAdvanced: () => {},
        onPatch,
      }),
      container,
    );

    const endpoint = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='Endpoint']"),
      "constrained endpoint input",
    );
    expect(endpoint.getAttribute("minlength")).toBeNull();
    expect(endpoint.getAttribute("maxlength")).toBeNull();
    expect(endpoint.pattern).toBe("");
    expect(endpoint.getAttribute("aria-describedby")).toBe(
      "config-field-s10-006c00610062006f007200610074006f00720079_s8-0065006e00640070006f0069006e0074-description",
    );
    endpoint.value = "Xlocal-apiY";
    endpoint.dispatchEvent(new Event("input", { bubbles: true }));
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "endpoint"], "Xlocal-apiY");

    endpoint.value = " a ";
    endpoint.dispatchEvent(new Event("input", { bubbles: true }));
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "endpoint"], " a ");
    endpoint.dispatchEvent(new Event("change", { bubbles: true }));
    expect(endpoint.value).toBe(" a ");
    expect(endpoint.getAttribute("aria-invalid")).toBe("false");
    expect(onPatch).not.toHaveBeenCalledWith(["laboratory", "endpoint"], "a");

    endpoint.value = "123";
    endpoint.dispatchEvent(new Event("input", { bubbles: true }));
    expect(endpoint.getAttribute("aria-invalid")).toBe("true");
    expect(onPatch).not.toHaveBeenCalledWith(["laboratory", "endpoint"], "123");

    endpoint.value = "";
    endpoint.dispatchEvent(new Event("input", { bubbles: true }));
    expect(endpoint.getAttribute("aria-invalid")).toBe("true");

    const optionalAlias = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='Optional Alias']"),
      "optional constrained string",
    );
    optionalAlias.value = "";
    optionalAlias.dispatchEvent(new Event("input", { bubbles: true }));
    expect(optionalAlias.getAttribute("aria-invalid")).toBe("false");
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "optionalAlias"], undefined);
    const explicitEmpty = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='Explicit Empty']"),
      "optional explicit empty string",
    );
    explicitEmpty.value = "";
    explicitEmpty.dispatchEvent(new Event("input", { bubbles: true }));
    expect(explicitEmpty.getAttribute("aria-invalid")).toBe("false");
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "explicitEmpty"], "");
    const glyph = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='Glyph']"),
      "unicode constrained string",
    );
    expect(glyph.getAttribute("maxlength")).toBeNull();
    glyph.value = "😀";
    glyph.dispatchEvent(new Event("input", { bubbles: true }));
    expect(glyph.getAttribute("aria-invalid")).toBe("false");
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "glyph"], "😀");
    const codes = expectElement(
      Array.from(container.querySelectorAll<HTMLElement>(".cfg-array")).find((block) =>
        block.textContent?.includes("Codes"),
      ),
      "patterned string array",
    );
    const addCode = expectElement(
      Array.from(codes.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add",
      ),
      "patterned string array add button",
    );
    expect(addCode.disabled).toBe(false);
    addCode.click();
    const codeDraftHost = expectElement(
      codes.querySelector<ConfigFormCollectionDraft>("openclaw-config-form-collection-draft"),
      "patterned string array draft host",
    );
    await codeDraftHost.updateComplete;
    const codeDraft = expectElement(
      codes.querySelector<HTMLElement>(".cfg-collection-draft"),
      "patterned string array draft",
    );
    expect(onPatch).not.toHaveBeenCalledWith(["laboratory", "codes"], expect.anything());
    const codeValue = expectElement(
      codeDraft.querySelector<HTMLInputElement>("input[aria-label='Add: Codes']"),
      "patterned string array draft value",
    );
    const commitCode = expectElement(
      Array.from(codeDraft.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add",
      ),
      "patterned string array draft commit",
    );
    codeValue.value = "abc";
    commitCode.click();
    await codeDraftHost.updateComplete;
    const invalidCodeValue = expectElement(
      codeDraftHost.querySelector<HTMLInputElement>("[data-collection-draft-value]"),
      "invalid patterned string array draft value",
    );
    expect(invalidCodeValue.getAttribute("aria-invalid")).toBe("true");
    expect(onPatch).not.toHaveBeenCalledWith(["laboratory", "codes"], expect.anything());
    invalidCodeValue.value = "123";
    invalidCodeValue.dispatchEvent(new Event("input", { bubbles: true }));
    await codeDraftHost.updateComplete;
    expectElement(
      Array.from(codeDraftHost.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add",
      ),
      "valid patterned string array draft commit",
    ).click();
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "codes"], ["123"]);
    await codeDraftHost.updateComplete;
    expect(codes.querySelector(".cfg-collection-draft")).toBeNull();
    const limited = expectElement(
      Array.from(container.querySelectorAll<HTMLElement>(".cfg-array")).find((block) =>
        block.textContent?.includes("Limited"),
      ),
      "max-items array",
    );
    const addLimited = expectElement(
      Array.from(limited.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add",
      ),
      "max-items array add button",
    );
    expect(addLimited.disabled).toBe(true);
    const provider = expectElement(
      container.querySelector<HTMLSelectElement>("select[aria-label='Provider']"),
      "named provider select",
    );
    expect(provider.getAttribute("aria-describedby")).toBe(
      "config-field-s10-006c00610062006f007200610074006f00720079_s8-00700072006f00760069006400650072-description",
    );
    const apiKey = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='API Key']"),
      "named secret input",
    );
    expect(apiKey.readOnly).toBe(true);

    const retryBudget = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='Retry Budget']"),
      "constrained retry budget input",
    );
    expect(retryBudget.min).toBe("2");
    expect(retryBudget.max).toBe("8");
    expect(retryBudget.step).toBe("2");
    const weightInput = expectElement(
      container.querySelector<HTMLInputElement>(".cfg-array input[aria-label='Weights']"),
      "bounded array input",
    );

    retryBudget.value = "";
    retryBudget.dispatchEvent(new Event("input", { bubbles: true }));
    expect(retryBudget.getAttribute("aria-invalid")).toBe("true");
    expect(retryBudget.validationMessage).not.toBe("");
    expect(onPatch).not.toHaveBeenCalledWith(["laboratory", "retryBudget"], undefined);

    retryBudget.value = "3";
    retryBudget.dispatchEvent(new Event("input", { bubbles: true }));
    expect(retryBudget.validationMessage).not.toBe("");
    retryBudget.dispatchEvent(new Event("change", { bubbles: true }));
    expect(retryBudget.value).toBe("4");
    expect(retryBudget.validationMessage).toBe("");
    expect(retryBudget.checkValidity()).toBe(true);
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "retryBudget"], 4);

    const increment = expectElement(
      container.querySelector<HTMLButtonElement>("button[aria-label='Retry Budget: +2']"),
      "retry increment button",
    );
    increment.click();
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "retryBudget"], 8);

    const addButton = expectElement(
      Array.from(
        expectElement(
          weightInput.closest<HTMLElement>(".cfg-array"),
          "bounded array",
        ).querySelectorAll<HTMLButtonElement>("button"),
      ).find((button) => button.textContent?.trim() === "Add"),
      "bounded array add button",
    );
    addButton.click();
    expect(onPatch).toHaveBeenCalledWith(["laboratory", "weights"], [2, 2]);
    container.remove();
  });

  it("generates unambiguous accessible IDs for nested paths", () => {
    expect(configFieldId(["a--b"], "description")).not.toBe(
      configFieldId(["a", "b"], "description"),
    );
    expect(configFieldId([1], "description")).not.toBe(configFieldId(["1"], "description"));
    expect(() => configFieldId(["\ud800"], "description")).not.toThrow();
    expect(configFieldId(["\ud800"], "description")).not.toBe(
      configFieldId(["\ufffd"], "description"),
    );
  });

  it("keeps rejected map-key edits synchronized with the persisted key", () => {
    const onPatch = vi.fn();
    const container = document.createElement("div");
    const analysis = analyzeConfigSchema({
      type: "object",
      properties: {
        accounts: { type: "object", additionalProperties: true },
      },
    });
    render(
      renderConfigForm({
        schema: analysis.schema,
        uiHints: {},
        unsupportedPaths: analysis.unsupportedPaths,
        value: { accounts: { alpha: {}, beta: {} } },
        showAdvanced: true,
        onShowAdvanced: () => {},
        onPatch,
      }),
      container,
    );

    const alpha = expectElement(
      Array.from(container.querySelectorAll<HTMLInputElement>(".cfg-map input")).find(
        (input) => input.value === "alpha",
      ),
      "alpha map key input",
    );
    alpha.value = " ";
    alpha.dispatchEvent(new Event("change", { bubbles: true }));
    expect(alpha.value).toBe("alpha");
    expect(onPatch).not.toHaveBeenCalled();

    alpha.value = "beta";
    alpha.dispatchEvent(new Event("change", { bubbles: true }));
    expect(alpha.value).toBe("alpha");
    expect(onPatch).not.toHaveBeenCalled();
  });

  it("commits typed map entries only after the local draft is valid", async () => {
    const onPatch = vi.fn();
    const container = document.createElement("div");
    document.body.append(container);
    const analysis = analyzeConfigSchema({
      type: "object",
      properties: {
        aliases: {
          type: "object",
          properties: {
            fixed: { type: "integer" },
          },
          additionalProperties: {
            type: "string",
            minLength: 3,
            pattern: "^[0-9]+$",
          },
        },
      },
    });
    render(
      renderConfigForm({
        schema: analysis.schema,
        uiHints: {},
        unsupportedPaths: analysis.unsupportedPaths,
        value: { aliases: {} },
        showAdvanced: true,
        onShowAdvanced: () => {},
        onPatch,
      }),
      container,
    );

    const addEntry = expectElement(
      Array.from(container.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add Entry",
      ),
      "typed map add button",
    );
    addEntry.click();
    const draftHost = expectElement(
      container.querySelector<ConfigFormCollectionDraft>("openclaw-config-form-collection-draft"),
      "typed map draft host",
    );
    await draftHost.updateComplete;
    const draft = expectElement(
      container.querySelector<HTMLElement>(".cfg-map .cfg-collection-draft"),
      "typed map draft",
    );
    const key = expectElement(
      draft.querySelector<HTMLInputElement>("[data-collection-draft-key]"),
      "typed map draft key",
    );
    const value = expectElement(
      draft.querySelector<HTMLInputElement>("[data-collection-draft-value]"),
      "typed map draft value",
    );
    const commit = expectElement(
      Array.from(draft.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add Entry",
      ),
      "typed map draft commit",
    );
    key.value = "fixed";
    key.dispatchEvent(new Event("input", { bubbles: true }));
    value.value = "123";
    value.dispatchEvent(new Event("input", { bubbles: true }));
    await draftHost.updateComplete;
    commit.click();
    await draftHost.updateComplete;
    const reservedKey = expectElement(
      draftHost.querySelector<HTMLInputElement>("[data-collection-draft-key]"),
      "reserved typed map draft key",
    );
    expect(reservedKey.getAttribute("aria-invalid")).toBe("true");
    expect(onPatch).not.toHaveBeenCalled();

    draftHost.dispatchEvent(
      new CustomEvent<ConfigFormCollectionDraftCommit>("config-collection-draft-commit", {
        bubbles: true,
        detail: { key: "constructor", value: "123" },
      }),
    );
    expect(onPatch).toHaveBeenCalledWith(["aliases"], { constructor: "123" });
    onPatch.mockClear();

    reservedKey.value = "primary";
    reservedKey.dispatchEvent(new Event("input", { bubbles: true }));
    const invalidValueInput = expectElement(
      draftHost.querySelector<HTMLInputElement>("[data-collection-draft-value]"),
      "typed map draft value after reserved key",
    );
    invalidValueInput.value = "abc";
    invalidValueInput.dispatchEvent(new Event("input", { bubbles: true }));
    await draftHost.updateComplete;
    expectElement(
      Array.from(draftHost.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add Entry",
      ),
      "invalid typed map draft commit",
    ).click();
    await draftHost.updateComplete;
    const invalidValue = expectElement(
      draftHost.querySelector<HTMLInputElement>("[data-collection-draft-value]"),
      "invalid typed map draft value",
    );
    expect(invalidValue.getAttribute("aria-invalid")).toBe("true");
    expect(onPatch).not.toHaveBeenCalled();

    invalidValue.value = "123";
    invalidValue.dispatchEvent(new Event("input", { bubbles: true }));
    await draftHost.updateComplete;
    expectElement(
      Array.from(draftHost.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add Entry",
      ),
      "valid typed map draft commit",
    ).click();
    expect(onPatch).toHaveBeenCalledWith(["aliases"], { primary: "123" });
    await draftHost.updateComplete;
    expect(container.querySelector(".cfg-map .cfg-collection-draft")).toBeNull();
    container.remove();
  });

  it("validates tuple collection drafts by position and additional-item policy", async () => {
    const host = document.createElement(
      "openclaw-config-form-collection-draft",
    ) as ConfigFormCollectionDraft;
    const commits = vi.fn();
    host.id = "tuple-draft";
    host.props = {
      schema: {
        type: "array",
        items: [
          {
            allOf: [
              { type: "string", pattern: "^[0-9]+$", enum: ["123", "12"] },
              { minLength: 3 },
              { anyOf: [{ const: "123" }, { const: "12" }] },
              { oneOf: [{ pattern: "^[0-9]+$" }, { const: "never" }] },
            ],
          },
          { type: "number", const: 0 },
        ],
        additionalItems: false,
      },
      label: "Tuple",
      disabled: false,
      identity: "tuple-draft",
      sourceIdentity: [],
    };
    host.addEventListener("config-collection-draft-commit", commits);
    document.body.append(host);

    host.openDraft();
    await host.updateComplete;
    const value = expectElement(
      host.querySelector<HTMLTextAreaElement>("[data-collection-draft-value]"),
      "tuple draft value",
    );
    value.value = '["123",-0]';
    value.dispatchEvent(new Event("input", { bubbles: true }));
    await host.updateComplete;
    expectElement(
      Array.from(host.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add",
      ),
      "valid tuple draft commit",
    ).click();
    expect(commits).toHaveBeenCalledTimes(1);

    host.openDraft();
    await host.updateComplete;
    const invalidValue = expectElement(
      host.querySelector<HTMLTextAreaElement>("[data-collection-draft-value]"),
      "invalid tuple draft value",
    );
    invalidValue.value = '["12",-0]';
    invalidValue.dispatchEvent(new Event("input", { bubbles: true }));
    await host.updateComplete;
    expectElement(
      Array.from(host.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add",
      ),
      "invalid tuple draft commit",
    ).click();
    await host.updateComplete;
    expect(commits).toHaveBeenCalledTimes(1);
    expect(
      expectElement(
        host.querySelector<HTMLTextAreaElement>("[data-collection-draft-value]"),
        "rejected tuple draft value",
      ).getAttribute("aria-invalid"),
    ).toBe("true");

    const extraValue = expectElement(
      host.querySelector<HTMLTextAreaElement>("[data-collection-draft-value]"),
      "tuple draft value with extra item",
    );
    extraValue.value = '["123",-0,2]';
    extraValue.dispatchEvent(new Event("input", { bubbles: true }));
    await host.updateComplete;
    expectElement(
      Array.from(host.querySelectorAll<HTMLButtonElement>("button")).find(
        (button) => button.textContent?.trim() === "Add",
      ),
      "tuple draft commit with extra item",
    ).click();
    await host.updateComplete;
    expect(commits).toHaveBeenCalledTimes(1);

    host.props = {
      ...host.props,
      sourceIdentity: [],
    };
    await host.updateComplete;
    expect(host.querySelector(".cfg-collection-draft")).toBeNull();
    host.remove();
  });

  it("clears scalar validity when a repeated row changes identity", () => {
    const onPatch = vi.fn();
    const container = document.createElement("div");
    const analysis = analyzeConfigSchema({
      type: "object",
      properties: {
        values: {
          type: "array",
          items: { type: "string", pattern: "^[0-9]+$" },
        },
      },
    });
    const renderValues = (values: string[]) => {
      render(
        renderConfigForm({
          schema: analysis.schema,
          uiHints: {},
          unsupportedPaths: analysis.unsupportedPaths,
          value: { values },
          showAdvanced: true,
          onShowAdvanced: () => {},
          onPatch,
        }),
        container,
      );
    };

    renderValues(["111", "222"]);
    const first = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='Values']"),
      "first repeated scalar input",
    );
    first.value = "abc";
    first.dispatchEvent(new Event("input", { bubbles: true }));
    expect(first.getAttribute("aria-invalid")).toBe("true");
    expect(first.validationMessage).not.toBe("");

    renderValues(["111", "333"]);
    const afterSiblingUpdate = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='Values']"),
      "repeated scalar input after sibling update",
    );
    expect(afterSiblingUpdate).toBe(first);
    expect(afterSiblingUpdate.value).toBe("abc");
    expect(afterSiblingUpdate.getAttribute("aria-invalid")).toBe("true");
    expect(afterSiblingUpdate.validationMessage).not.toBe("");

    renderValues(["111"]);
    const shifted = expectElement(
      container.querySelector<HTMLInputElement>("input[aria-label='Values']"),
      "shifted repeated scalar input",
    );
    expect(shifted).toBe(first);
    expect(shifted.value).toBe("111");
    expect(shifted.getAttribute("aria-invalid")).toBe("false");
    expect(shifted.validationMessage).toBe("");
  });

  it("retains invalid JSON drafts with an inline accessible error", () => {
    const onPatch = vi.fn();
    const container = document.createElement("div");
    const primaryValue = { enabled: true };
    const analysis = analyzeConfigSchema({
      type: "object",
      properties: {
        accounts: { type: "object", additionalProperties: true },
      },
    });
    render(
      renderConfigForm({
        schema: analysis.schema,
        uiHints: {},
        unsupportedPaths: analysis.unsupportedPaths,
        value: { accounts: { primary: primaryValue, secondary: { enabled: false } } },
        showAdvanced: true,
        onShowAdvanced: () => {},
        onPatch,
      }),
      container,
    );

    const textarea = expectElement(
      container.querySelector<HTMLTextAreaElement>(".cfg-map textarea"),
      "JSON map value",
    );
    expect(textarea.getAttribute("aria-label")).toBe("primary: JSON value");
    textarea.value = '{"enabled":';
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    textarea.dispatchEvent(new Event("change", { bubbles: true }));

    expect(textarea.value).toBe('{"enabled":');
    expect(textarea.getAttribute("aria-invalid")).toBe("true");
    const error = expectElement(
      container.querySelector<HTMLElement>("[role='alert']"),
      "JSON error",
    );
    expect(error.hidden).toBe(false);
    expect(error.textContent).toContain("valid JSON");
    expect(onPatch).not.toHaveBeenCalled();

    textarea.value = '{"enabled":false}';
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    textarea.dispatchEvent(new Event("change", { bubbles: true }));
    expect(textarea.getAttribute("aria-invalid")).toBe("false");
    expect(error.hidden).toBe(true);
    expect(onPatch).toHaveBeenCalledWith(["accounts", "primary"], { enabled: false });

    textarea.value = '{"enabled":';
    textarea.dispatchEvent(new Event("input", { bubbles: true }));
    expect(textarea.getAttribute("aria-invalid")).toBe("true");
    render(
      renderConfigForm({
        schema: analysis.schema,
        uiHints: {},
        unsupportedPaths: analysis.unsupportedPaths,
        value: { accounts: { primary: primaryValue, secondary: { enabled: true } } },
        showAdvanced: true,
        onShowAdvanced: () => {},
        onPatch,
      }),
      container,
    );
    const siblingUpdateTextarea = expectElement(
      container.querySelector<HTMLTextAreaElement>(
        ".cfg-map textarea[aria-label='primary: JSON value']",
      ),
      "JSON map value after sibling update",
    );
    expect(siblingUpdateTextarea.value).toBe('{"enabled":');
    expect(siblingUpdateTextarea.getAttribute("aria-invalid")).toBe("true");
    expect(siblingUpdateTextarea.validationMessage).not.toBe("");
    expect(error.hidden).toBe(false);

    render(
      renderConfigForm({
        schema: analysis.schema,
        uiHints: {},
        unsupportedPaths: analysis.unsupportedPaths,
        value: { accounts: { primary: { enabled: true } } },
        showAdvanced: true,
        onShowAdvanced: () => {},
        onPatch,
      }),
      container,
    );
    const resetTextarea = expectElement(
      container.querySelector<HTMLTextAreaElement>(".cfg-map textarea"),
      "externally reset JSON map value",
    );
    expect(resetTextarea.value).toContain('"enabled": true');
    expect(resetTextarea.getAttribute("aria-invalid")).toBe("false");
    expect(resetTextarea.validationMessage).toBe("");
    expect(error.hidden).toBe(true);
  });
});
