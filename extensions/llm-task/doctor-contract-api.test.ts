import { describe, expect, it } from "vitest";
import { legacyConfigRules, normalizeCompatibilityConfig } from "./doctor-contract-api.js";

describe("llm-task doctor contract", () => {
  it("surfaces pre-policy entries and converges after migration", () => {
    const rule = legacyConfigRules.find(
      (candidate) => candidate.path.join(".") === "plugins.entries.llm-task",
    ) as { match?: (value: unknown, root: Record<string, unknown>) => boolean } | undefined;
    expect(rule?.match?.({ enabled: true }, {})).toBe(true);
    expect(
      rule?.match?.({ llm: { allowModelOverride: true, allowAuthProfileOverride: true } }, {}),
    ).toBe(false);
    expect(
      rule?.match?.({ llm: { allowModelOverride: false, allowAuthProfileOverride: false } }, {}),
    ).toBe(false);
  });

  it("moves shipped model policy and grants the shipped override capabilities", () => {
    const result = normalizeCompatibilityConfig({
      cfg: {
        plugins: {
          entries: {
            "llm-task": {
              enabled: true,
              config: {
                defaultModel: "gpt-5.6-sol",
                allowedModels: ["openai/gpt-5.6-sol"],
              },
            },
          },
        },
      },
    });

    expect(result.config.plugins?.entries?.["llm-task"]).toEqual({
      enabled: true,
      llm: {
        allowModelOverride: true,
        allowAuthProfileOverride: true,
        allowedModels: ["openai/gpt-5.6-sol"],
      },
      config: { defaultModel: "gpt-5.6-sol" },
    });
    expect(result.changes).toHaveLength(2);
  });

  it("keeps explicit canonical policy authoritative", () => {
    const result = normalizeCompatibilityConfig({
      cfg: {
        plugins: {
          entries: {
            "llm-task": {
              llm: {
                allowModelOverride: false,
                allowAuthProfileOverride: false,
                allowedModels: ["anthropic/claude-haiku-4-5"],
              },
              config: { allowedModels: ["openai/gpt-5.6-sol"] },
            },
          },
        },
      },
    });

    expect(result.config.plugins?.entries?.["llm-task"]).toEqual({
      llm: {
        allowModelOverride: false,
        allowAuthProfileOverride: false,
        allowedModels: ["anthropic/claude-haiku-4-5"],
      },
      config: {},
    });
    expect(result.changes).toEqual([
      "Removed plugins.entries.llm-task.config.allowedModels; existing plugins.entries.llm-task.llm.allowedModels remains authoritative.",
    ]);
  });

  it("preserves the unrestricted meaning of an empty legacy allowlist", () => {
    const result = normalizeCompatibilityConfig({
      cfg: {
        plugins: {
          entries: {
            "llm-task": {
              enabled: true,
              config: { allowedModels: [] },
            },
          },
        },
      },
    });

    expect(result.config.plugins?.entries?.["llm-task"]?.llm).toEqual({
      allowModelOverride: true,
      allowAuthProfileOverride: true,
    });
    expect(result.changes).toContain(
      "Removed empty plugins.entries.llm-task.config.allowedModels; unrestricted model selection remains unchanged.",
    );
  });

  it("does not give legacy literal wildcards or noncanonical refs new meaning", () => {
    const result = normalizeCompatibilityConfig({
      cfg: {
        plugins: {
          entries: {
            "llm-task": {
              config: {
                allowedModels: ["*", " openai/gpt-5.4 ", "OpenAI/gpt-5.5", "openai/gpt-5.6"],
              },
            },
          },
        },
      },
    });

    expect(result.config.plugins?.entries?.["llm-task"]?.llm?.allowedModels).toEqual([
      "openai/gpt-5.6",
    ]);
  });

  it("keeps a nonempty legacy wildcard-only allowlist fail closed", () => {
    const result = normalizeCompatibilityConfig({
      cfg: {
        plugins: {
          entries: {
            "llm-task": { config: { allowedModels: ["*"] } },
          },
        },
      },
    });

    expect(result.config.plugins?.entries?.["llm-task"]?.llm?.allowedModels).toEqual([]);
  });

  it.each(["openai/gpt-5.6", null, [123, null]])(
    "keeps malformed legacy allowlist %j fail closed",
    (allowedModels) => {
      const result = normalizeCompatibilityConfig({
        cfg: {
          plugins: {
            entries: {
              "llm-task": { config: { allowedModels } },
            },
          },
        },
      });

      expect(result.config.plugins?.entries?.["llm-task"]?.llm?.allowedModels).toEqual([]);
    },
  );

  it("is idempotent after migration", () => {
    const cfg = {
      plugins: {
        entries: {
          "llm-task": {
            llm: { allowModelOverride: true, allowAuthProfileOverride: true },
            config: {},
          },
        },
      },
    } as const;
    const result = normalizeCompatibilityConfig({ cfg });
    expect(result.config).toBe(cfg);
    expect(result.changes).toEqual([]);
  });
});
