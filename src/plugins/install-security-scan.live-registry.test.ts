import fs from "node:fs";
import path from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import { listPluginCommands } from "./commands.js";
import { initializeGlobalHookRunner, resetGlobalHookRunner } from "./hook-runner-global.js";
import { createMockPluginRegistry } from "./hooks.test-fixtures.js";
import {
  scanInstallPayload,
  scanSkillInstall,
  withInstallScanEnv,
  writeBeforeInstallBlocker,
} from "./install-security-scan.integration.test-support.js";
import {
  cleanupPluginLoaderFixturesForTest,
  makeTempDir,
  resetPluginLoaderTestStateForTest,
  useNoBundledPlugins,
  writePlugin,
} from "./loader.test-fixtures.js";
import { createEmptyPluginRegistry } from "./registry-empty.js";
import {
  collectLivePluginRegistries,
  getActivePluginRegistry,
  getPluginRegistryWorkspaceDir,
  pinActivePluginChannelRegistry,
  setActivePluginRegistry,
} from "./runtime.js";
import { ensurePluginRegistryLoaded } from "./runtime/runtime-registry-loader.js";

function writeCommandPlugin(id: string, dir?: string) {
  return writePlugin({
    id,
    ...(dir ? { dir } : {}),
    filename: dir ? "index.cjs" : `${id}.cjs`,
    body: `module.exports = { id: ${JSON.stringify(id)}, register(api) {
      api.registerCommand({
        name: "hello",
        description: "hello",
        handler: () => ({ text: "hello" }),
      });
    } };`,
  });
}

function writeStatefulBeforeInstallBlocker(id: string) {
  const plugin = writePlugin({
    id,
    filename: `${id}.cjs`,
    body: `module.exports = { id: ${JSON.stringify(id)}, register(api) {
      globalThis.__openclawInstallScannerInstances =
        (globalThis.__openclawInstallScannerInstances || 0) + 1;
      const instance = globalThis.__openclawInstallScannerInstances;
      api.on("before_install", () => ({
        block: true,
        blockReason: "scanner instance " + instance,
      }));
    } };`,
  });
  const manifestPath = path.join(plugin.dir, "openclaw.plugin.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  manifest.activation = { onHooks: ["before_install"] };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");
  return plugin;
}

function writeConfigurableBeforeInstallBlocker(id: string) {
  const plugin = writePlugin({
    id,
    filename: `${id}.cjs`,
    body: `module.exports = { id: ${JSON.stringify(id)}, register(api) {
      const shouldBlock =
        api.pluginConfig?.block === true || api.config.commands?.native === true;
      api.on("before_install", () => shouldBlock ? ({
        block: true,
        blockReason: "current scanner config blocks",
      }) : undefined);
    } };`,
  });
  const manifestPath = path.join(plugin.dir, "openclaw.plugin.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  manifest.activation = { onHooks: ["before_install"] };
  manifest.configSchema = {
    type: "object",
    properties: {
      block: { type: "boolean" },
    },
    additionalProperties: false,
  };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");
  return plugin;
}

function writeLabeledBeforeInstallBlocker(
  id: string,
  dir: string,
  label: string,
  options: { activationHint?: boolean } = {},
) {
  const plugin = writePlugin({
    id,
    dir,
    filename: "index.cjs",
    body: `module.exports = { id: ${JSON.stringify(id)}, register(api) {
      api.on("before_install", () => ({
        block: true,
        blockReason: ${JSON.stringify(label)},
      }));
    } };`,
  });
  const manifestPath = path.join(plugin.dir, "openclaw.plugin.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  if (options.activationHint !== false) {
    manifest.activation = { onHooks: ["before_install"] };
  }
  fs.writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");
  return plugin;
}

afterEach(() => {
  Reflect.deleteProperty(globalThis, "__openclawInstallScannerInstances");
  resetGlobalHookRunner();
  resetPluginLoaderTestStateForTest();
});

afterAll(() => {
  cleanupPluginLoaderFixturesForTest();
});

describe("live install hook provider registries", () => {
  it("preserves active plugin commands while activating a lazy hook provider", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const commandPlugin = writeCommandPlugin("command-plugin");
    const scanner = writeBeforeInstallBlocker("scanner");
    const config = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [commandPlugin.file, scanner.file] },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config,
        workspaceDir,
        onlyPluginIds: [commandPlugin.id],
      });
      expect(listPluginCommands().map((command) => command.name)).toContain("hello");
      const scanResult = await scanInstallPayload(config);
      expect(listPluginCommands().map((command) => command.name)).toContain("hello");
      return scanResult;
    });

    expect(result).toEqual({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked staged target payload",
      },
    });
  });

  it("reuses an active stateful hook provider instead of registering it again", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeStatefulBeforeInstallBlocker("stateful-scanner");
    const config = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [scanner.file] },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config,
        workspaceDir,
        onlyPluginIds: [scanner.id],
      });
      return await scanInstallPayload(config);
    });

    expect(result?.blocked?.reason).toBe("scanner instance 1");
    expect(Reflect.get(globalThis, "__openclawInstallScannerInstances")).toBe(1);
  });

  it.each([
    { name: "plugin config", scope: "plugin" as const },
    { name: "host config", scope: "host" as const },
  ])("reloads a live scanner when its $name changes", async ({ scope }) => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeConfigurableBeforeInstallBlocker("reconfigured-scanner");
    const configFor = (blocks: boolean) => ({
      agents: { defaults: { workspace: workspaceDir } },
      ...(scope === "host" ? { commands: { native: blocks } } : {}),
      plugins: {
        load: { paths: [scanner.file] },
        entries: {
          [scanner.id]: { config: { block: scope === "plugin" && blocks } },
        },
      },
    });

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config: configFor(false),
        workspaceDir,
        onlyPluginIds: [scanner.id],
      });
      return await scanInstallPayload(configFor(true));
    });

    expect(result?.blocked?.reason).toBe("current scanner config blocks");
  });

  it("keeps an explicitly trusted active hook without an activation declaration", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeLabeledBeforeInstallBlocker(
      "undeclared-active-scanner",
      path.join(makeTempDir(), "undeclared-active-scanner"),
      "undeclared active scanner",
      { activationHint: false },
    );
    const config = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [scanner.file] },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config,
        workspaceDir,
        onlyPluginIds: [scanner.id],
      });
      return await scanInstallPayload(config);
    });

    expect(result?.blocked?.reason).toBe("undeclared active scanner");
  });

  it("stops reusing an active scanner after its load path trust is removed", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeLabeledBeforeInstallBlocker(
      "removed-load-path-scanner",
      path.join(makeTempDir(), "removed-load-path-scanner"),
      "removed load path scanner",
      { activationHint: false },
    );
    const enabledConfig = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [scanner.file] },
      },
    };
    const revokedConfig = {
      agents: { defaults: { workspace: workspaceDir } },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config: enabledConfig,
        workspaceDir,
        onlyPluginIds: [scanner.id],
      });
      return await scanInstallPayload(revokedConfig);
    });

    expect(result).toBeUndefined();
  });

  it("loads the current same-id scanner source instead of reusing an active old source", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scannerId = "replaced-source-scanner";
    const scannerA = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(makeTempDir(), "scanner-a"),
      "old scanner source",
    );
    const scannerB = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(makeTempDir(), "scanner-b"),
      "current scanner source",
    );
    const configFor = (scannerFile: string) => ({
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [scannerFile] },
      },
    });

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config: configFor(scannerA.file),
        workspaceDir,
        onlyPluginIds: [scannerId],
      });
      return await scanInstallPayload(configFor(scannerB.file));
    });

    expect(result?.blocked?.reason).toBe("current scanner source");
  });

  it("loads the retargeted same-id scanner behind a configured symlink", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scannerId = "retargeted-symlink-scanner";
    const scannerA = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(makeTempDir(), "scanner-a"),
      "old symlink target",
    );
    const scannerB = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(makeTempDir(), "scanner-b"),
      "current symlink target",
    );
    const linkPath = path.join(makeTempDir(), "scanner-link");
    fs.symlinkSync(scannerA.dir, linkPath, "dir");
    const config = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [linkPath] },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config,
        workspaceDir,
        onlyPluginIds: [scannerId],
      });
      fs.unlinkSync(linkPath);
      fs.symlinkSync(scannerB.dir, linkPath, "dir");
      return await scanInstallPayload(config);
    });

    expect(result?.blocked?.reason).toBe("current symlink target");
  });

  it("does not reuse hook ownership after a configured symlink is retargeted", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scannerId = "removed-symlink-hook-scanner";
    const scannerA = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(makeTempDir(), "scanner-a"),
      "old declared scanner",
    );
    const scannerB = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(makeTempDir(), "scanner-b"),
      "current undeclared scanner",
      { activationHint: false },
    );
    const linkPath = path.join(makeTempDir(), "scanner-link");
    fs.symlinkSync(scannerA.dir, linkPath, "dir");
    const config = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [linkPath] },
      },
    };

    const [firstResult, secondResult] = await withInstallScanEnv(stateDir, async () => {
      const first = await scanInstallPayload(config, "first");
      fs.unlinkSync(linkPath);
      fs.symlinkSync(scannerB.dir, linkPath, "dir");
      return [first, await scanInstallPayload(config, "second")];
    });

    expect(firstResult?.blocked?.reason).toBe("old declared scanner");
    expect(secondResult).toBeUndefined();
  });

  it("fully loads a hook provider that is active only through a hookless setup runtime", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker("setup-loaded-scanner");
    const config = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [scanner.file] },
      },
    };
    const setupRegistry = createEmptyPluginRegistry();
    setupRegistry.plugins.push({
      id: scanner.id,
      source: scanner.file,
      origin: "config",
      enabled: true,
      status: "loaded",
    } as never);
    setActivePluginRegistry(setupRegistry, "setup-runtime", "default", workspaceDir);

    const result = await withInstallScanEnv(stateDir, () => scanInstallPayload(config));

    expect(result?.blocked?.reason).toBe("blocked staged target payload");
  });

  it("does not replace the active registry when scanning another workspace", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceA = makeTempDir();
    const workspaceB = makeTempDir();
    const commandPlugin = writeCommandPlugin(
      "workspace-a-command",
      path.join(workspaceA, ".openclaw", "extensions", "workspace-a-command"),
    );
    const scanner = writeBeforeInstallBlocker(
      "workspace-b-scanner",
      path.join(workspaceB, ".openclaw", "extensions", "workspace-b-scanner"),
    );
    const config = {
      plugins: {
        allow: [commandPlugin.id, scanner.id],
        entries: {
          [commandPlugin.id]: { enabled: true },
          [scanner.id]: { enabled: true },
        },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config,
        workspaceDir: workspaceA,
        onlyPluginIds: [commandPlugin.id],
      });
      expect(listPluginCommands().map((command) => command.name)).toContain("hello");
      const scanResult = await scanSkillInstall(config, workspaceB);
      expect(listPluginCommands().map((command) => command.name)).toContain("hello");
      return scanResult;
    });

    expect(result?.blocked?.reason).toBe("blocked staged target payload");
  });

  it("does not reuse a same-id scanner from another workspace", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceA = makeTempDir();
    const workspaceB = makeTempDir();
    const scannerId = "workspace-scanner";
    const scannerA = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(workspaceA, ".openclaw", "extensions", scannerId),
      "workspace A scanner",
    );
    writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(workspaceB, ".openclaw", "extensions", scannerId),
      "workspace B scanner",
    );
    const config = {
      plugins: {
        allow: [scannerId],
        entries: {
          [scannerId]: { enabled: true },
        },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config,
        workspaceDir: workspaceA,
        onlyPluginIds: [scannerA.id],
      });
      return await scanSkillInstall(config, workspaceB);
    });

    expect(result?.blocked?.reason).toBe("workspace B scanner");
  });

  it("does not fall back to hooks from another active workspace", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceA = makeTempDir();
    const workspaceB = makeTempDir();
    const scanner = writeLabeledBeforeInstallBlocker(
      "workspace-a-only-scanner",
      path.join(workspaceA, ".openclaw", "extensions", "workspace-a-only-scanner"),
      "workspace A scanner",
    );
    const enabledConfig = {
      plugins: {
        allow: [scanner.id],
        entries: {
          [scanner.id]: { enabled: true },
        },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config: enabledConfig,
        workspaceDir: workspaceA,
        onlyPluginIds: [scanner.id],
      });
      return await scanSkillInstall({}, workspaceB);
    });

    expect(result).toBeUndefined();
  });

  it("preserves an explicitly initialized SDK install gate outside plugin policy", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const sdkRegistry = createMockPluginRegistry([
      {
        hookName: "before_install",
        pluginId: "sdk-install-gate",
        handler: () => ({
          block: true,
          blockReason: "SDK install gate",
        }),
      },
    ]);
    sdkRegistry.hooks = [];
    setActivePluginRegistry(createEmptyPluginRegistry(), "active", "default", workspaceDir);
    initializeGlobalHookRunner(sdkRegistry);

    const result = await withInstallScanEnv(stateDir, () =>
      scanInstallPayload({
        agents: { defaults: { workspace: workspaceDir } },
        plugins: {
          enabled: false,
          allow: ["other"],
          deny: ["sdk-install-gate"],
        },
      }),
    );

    expect(result?.blocked?.reason).toBe("SDK install gate");
  });

  it("uses the target active scanner instead of a same-id pinned scanner", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceA = makeTempDir();
    const workspaceB = makeTempDir();
    const scannerId = "pinned-workspace-scanner";
    const scannerA = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(workspaceA, ".openclaw", "extensions", scannerId),
      "pinned workspace A scanner",
    );
    const scannerB = writeLabeledBeforeInstallBlocker(
      scannerId,
      path.join(workspaceB, ".openclaw", "extensions", scannerId),
      "active workspace B scanner",
    );
    const config = {
      plugins: {
        allow: [scannerId],
        entries: {
          [scannerId]: { enabled: true },
        },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config,
        workspaceDir: workspaceA,
        onlyPluginIds: [scannerA.id],
      });
      const workspaceARegistry = getActivePluginRegistry();
      if (!workspaceARegistry) {
        throw new Error("expected workspace A plugin registry");
      }
      pinActivePluginChannelRegistry(workspaceARegistry);
      ensurePluginRegistryLoaded({
        config,
        workspaceDir: workspaceB,
        onlyPluginIds: [scannerB.id],
      });
      return await scanSkillInstall(config, workspaceB);
    });

    expect(result?.blocked?.reason).toBe("active workspace B scanner");
  });

  it("keeps a same-workspace pinned scanner during a scoped active swap", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeLabeledBeforeInstallBlocker(
      "legacy-pinned-scanner",
      path.join(workspaceDir, ".openclaw", "extensions", "legacy-pinned-scanner"),
      "same-workspace pinned scanner",
    );
    const config = {
      plugins: {
        allow: [scanner.id],
        entries: {
          [scanner.id]: { enabled: true },
        },
      },
    };

    const result = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config,
        workspaceDir,
        onlyPluginIds: [scanner.id],
      });
      const startupRegistry = getActivePluginRegistry();
      if (!startupRegistry) {
        throw new Error("expected startup plugin registry");
      }
      expect(startupRegistry.typedHooks.map((hook) => hook.hookName)).toContain("before_install");
      expect(getPluginRegistryWorkspaceDir(startupRegistry)).toBe(workspaceDir);
      pinActivePluginChannelRegistry(startupRegistry);
      setActivePluginRegistry(createEmptyPluginRegistry(), "scoped", "default", workspaceDir);
      expect(collectLivePluginRegistries()).toContain(startupRegistry);
      return await scanSkillInstall(config, workspaceDir);
    });

    expect(result?.blocked?.reason).toBe("same-workspace pinned scanner");
  });

  it.each([
    { name: "it is disabled", policy: "disabled" as const },
    { name: "a restrictive allowlist excludes it", policy: "allowlist" as const },
  ])("stops dispatching a loaded hook provider when $name", async ({ policy }) => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker("scanner");
    const enabledConfig = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        load: { paths: [scanner.file] },
      },
    };
    const currentConfig = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins:
        policy === "disabled"
          ? {
              load: { paths: [scanner.file] },
              entries: { [scanner.id]: { enabled: false } },
            }
          : {
              allow: ["other"],
              entries: { other: { enabled: true } },
            },
    };

    const [enabledResult, currentResult] = await withInstallScanEnv(stateDir, async () => {
      ensurePluginRegistryLoaded({
        config: enabledConfig,
        workspaceDir,
        onlyPluginIds: [scanner.id],
      });
      return [
        await scanInstallPayload(enabledConfig, "first"),
        await scanInstallPayload(currentConfig, "second"),
      ];
    });

    expect(enabledResult?.blocked?.reason).toBe("blocked staged target first");
    expect(currentResult).toBeUndefined();
  });
});
