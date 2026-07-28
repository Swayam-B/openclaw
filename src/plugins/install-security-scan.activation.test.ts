import fs from "node:fs";
import path from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import {
  clearContextEnginesForOwner,
  getContextEngineRegistration,
} from "../context-engine/registry.js";
import { withEnvAsync } from "../test-utils/env.js";
import { listPluginCommands } from "./commands.js";
import { resetGlobalHookRunner } from "./hook-runner-global.js";
import { initializeGlobalHookRunner } from "./hook-runner-global.js";
import { createMockPluginRegistry } from "./hooks.test-fixtures.js";
import {
  evaluateSkillInstallPolicyRuntime,
  scanBundleInstallSourceRuntime,
  scanFileInstallSourceRuntime,
} from "./install-security-scan.runtime.js";
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

function writeBeforeInstallBlocker(
  id: string,
  dir?: string,
  options: { fullRegistrationOnly?: boolean; installScanRegistrationOnly?: boolean } = {},
) {
  const plugin = writePlugin({
    id,
    ...(dir ? { dir } : {}),
    filename: dir ? "index.cjs" : `${id}.cjs`,
    body: `module.exports = { id: ${JSON.stringify(id)}, register(api) {
      ${options.fullRegistrationOnly ? 'if (api.registrationMode !== "full") return;' : ""}
      ${options.installScanRegistrationOnly ? 'if (api.registrationMode !== "install-scan") return;' : ""}
      api.on("before_install", (event) => ({
        block: true,
        blockReason: "blocked staged target " + event.targetName,
      }));
    } };`,
  });
  const manifestPath = path.join(plugin.dir, "openclaw.plugin.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  manifest.activation = { onHooks: ["before_install"] };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");
  return plugin;
}

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

function writeContextEngineBeforeInstallBlocker(id: string, contextEngineId: string) {
  const plugin = writePlugin({
    id,
    filename: `${id}.cjs`,
    body: `module.exports = { id: ${JSON.stringify(id)}, register(api) {
      api.registerContextEngine(${JSON.stringify(contextEngineId)}, () => ({}));
      api.on("before_install", () => ({
        block: true,
        blockReason: "blocked by context-engine scanner",
      }));
    } };`,
  });
  const manifestPath = path.join(plugin.dir, "openclaw.plugin.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
  manifest.activation = { onHooks: ["before_install"] };
  fs.writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");
  return plugin;
}

afterEach(() => {
  Reflect.deleteProperty(globalThis, "__openclawInstallScannerInstances");
  clearContextEnginesForOwner("plugin:context-engine-scanner");
  resetGlobalHookRunner();
  resetPluginLoaderTestStateForTest();
});

afterAll(() => {
  cleanupPluginLoaderFixturesForTest();
});

describe("install hook provider activation", () => {
  it("discovers and loads a configured hook provider before install dispatch", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker("Scanner-X");
    const config = {
      plugins: {
        load: { paths: [scanner.file] },
      },
    };
    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanFileInstallSourceRuntime({
          config,
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        }),
    );

    expect(result).toEqual({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked staged target payload",
      },
    });
  });

  it("loads a hook provider in transient install-scan mode", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker("install-scan-mode-scanner", undefined, {
      installScanRegistrationOnly: true,
    });
    const config = {
      plugins: {
        load: { paths: [scanner.file] },
      },
    };

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanFileInstallSourceRuntime({
          config,
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        }),
    );

    expect(result?.blocked?.reason).toBe("blocked staged target payload");
  });

  it("fails closed when a declared provider omits its install-scan registration", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker("full-only-scanner", undefined, {
      fullRegistrationOnly: true,
    });

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanFileInstallSourceRuntime({
          config: { plugins: { load: { paths: [scanner.file] } } },
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        }),
    );

    expect(result?.blocked).toEqual({
      code: "security_scan_failed",
      reason: expect.stringContaining(
        "hook providers did not register before_install in install-scan mode: full-only-scanner",
      ),
    });
  });

  it("does not treat the broad hook capability as an install scanner declaration", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const plugin = writePlugin({
      id: "agent-run-hook",
      filename: "agent-run-hook.cjs",
      body: `module.exports = { id: "agent-run-hook", register(api) {
        api.on("before_agent_run", () => ({ block: false }));
      } };`,
    });
    const manifestPath = path.join(plugin.dir, "openclaw.plugin.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    manifest.activation = { onCapabilities: ["hook"] };
    fs.writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanFileInstallSourceRuntime({
          config: { plugins: { load: { paths: [plugin.file] } } },
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        }),
    );

    expect(result).toBeUndefined();
  });

  it("loads a memory-capable scanner even when another plugin owns the memory slot", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker("memory-scanner");
    const manifestPath = path.join(scanner.dir, "openclaw.plugin.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    manifest.kind = "memory";
    fs.writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanFileInstallSourceRuntime({
          config: {
            plugins: {
              allow: [scanner.id],
              entries: { [scanner.id]: { enabled: true } },
              load: { paths: [scanner.file] },
              slots: { memory: "memory-core" },
            },
          },
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        }),
    );

    expect(result?.blocked?.reason).toBe("blocked staged target payload");
  });

  it("does not leak context engines from an isolated full-mode scanner", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const contextEngineId = "isolated-scanner-context-engine";
    const scanner = writeContextEngineBeforeInstallBlocker(
      "context-engine-scanner",
      contextEngineId,
    );
    const config = {
      plugins: {
        load: { paths: [scanner.file] },
      },
    };

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanFileInstallSourceRuntime({
          config,
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        }),
    );

    expect(result?.blocked?.reason).toBe("blocked by context-engine scanner");
    expect(getContextEngineRegistration(contextEngineId)).toBeUndefined();
  });

  it("does not execute a staged plugin as its own first-install scanner", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const stagedScanner = writeBeforeInstallBlocker("staged-scanner");

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanBundleInstallSourceRuntime({
          config: {},
          logger: {},
          pluginId: "staged-scanner",
          sourceDir: stagedScanner.dir,
        }),
    );

    expect(result).toBeUndefined();
  });

  it("discovers a hook provider from the target skill workspace", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker(
      "workspace-scanner",
      path.join(workspaceDir, ".openclaw", "extensions", "workspace-scanner"),
    );
    const config = {
      plugins: {
        allow: [scanner.id],
        entries: {
          [scanner.id]: { enabled: true },
        },
      },
    };
    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await evaluateSkillInstallPolicyRuntime({
          config,
          workspaceDir,
          installId: "node",
          logger: {},
          origin: { type: "workspace" },
          skillName: "payload",
          sourceDir: makeTempDir(),
        }),
    );

    expect(result).toEqual({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked staged target payload",
      },
    });
  });

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

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
        ensurePluginRegistryLoaded({
          config,
          workspaceDir,
          onlyPluginIds: [commandPlugin.id],
        });
        expect(listPluginCommands().map((command) => command.name)).toContain("hello");
        const scanResult = await scanFileInstallSourceRuntime({
          config,
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        });
        expect(listPluginCommands().map((command) => command.name)).toContain("hello");
        return scanResult;
      },
    );

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

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
        ensurePluginRegistryLoaded({
          config,
          workspaceDir,
          onlyPluginIds: [scanner.id],
        });
        return await scanFileInstallSourceRuntime({
          config,
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        });
      },
    );

    expect(result?.blocked?.reason).toBe("scanner instance 1");
    expect(Reflect.get(globalThis, "__openclawInstallScannerInstances")).toBe(1);
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

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanFileInstallSourceRuntime({
          config,
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        }),
    );

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

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
        ensurePluginRegistryLoaded({
          config,
          workspaceDir: workspaceA,
          onlyPluginIds: [commandPlugin.id],
        });
        expect(listPluginCommands().map((command) => command.name)).toContain("hello");
        const scanResult = await evaluateSkillInstallPolicyRuntime({
          config,
          workspaceDir: workspaceB,
          installId: "node",
          logger: {},
          origin: { type: "workspace" },
          skillName: "payload",
          sourceDir: makeTempDir(),
        });
        expect(listPluginCommands().map((command) => command.name)).toContain("hello");
        return scanResult;
      },
    );

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

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
        ensurePluginRegistryLoaded({
          config,
          workspaceDir: workspaceA,
          onlyPluginIds: [scannerA.id],
        });
        return await evaluateSkillInstallPolicyRuntime({
          config,
          workspaceDir: workspaceB,
          installId: "node",
          logger: {},
          origin: { type: "workspace" },
          skillName: "payload",
          sourceDir: makeTempDir(),
        });
      },
    );

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

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
        ensurePluginRegistryLoaded({
          config: enabledConfig,
          workspaceDir: workspaceA,
          onlyPluginIds: [scanner.id],
        });
        return await evaluateSkillInstallPolicyRuntime({
          config: {},
          workspaceDir: workspaceB,
          installId: "node",
          logger: {},
          origin: { type: "workspace" },
          skillName: "payload",
          sourceDir: makeTempDir(),
        });
      },
    );

    expect(result).toBeUndefined();
  });

  it("preserves an explicitly initialized SDK install gate beside an active registry", async () => {
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

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () =>
        await scanFileInstallSourceRuntime({
          config: { agents: { defaults: { workspace: workspaceDir } } },
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
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

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
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
        return await evaluateSkillInstallPolicyRuntime({
          config,
          workspaceDir: workspaceB,
          installId: "node",
          logger: {},
          origin: { type: "workspace" },
          skillName: "payload",
          sourceDir: makeTempDir(),
        });
      },
    );

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
      { activationHint: false },
    );
    const config = {
      plugins: {
        allow: [scanner.id],
        entries: {
          [scanner.id]: { enabled: true },
        },
      },
    };

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
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
        return await evaluateSkillInstallPolicyRuntime({
          config,
          workspaceDir,
          installId: "node",
          logger: {},
          origin: { type: "workspace" },
          skillName: "payload",
          sourceDir: makeTempDir(),
        });
      },
    );

    expect(result?.blocked?.reason).toBe("same-workspace pinned scanner");
  });

  it("stops dispatching a hook provider after it is disabled", async () => {
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
    const disabledConfig = {
      ...enabledConfig,
      plugins: {
        ...enabledConfig.plugins,
        entries: {
          [scanner.id]: { enabled: false },
        },
      },
    };

    const [enabledResult, disabledResult] = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
        ensurePluginRegistryLoaded({
          config: enabledConfig,
          workspaceDir,
          onlyPluginIds: [scanner.id],
        });
        return [
          await scanFileInstallSourceRuntime({
            config: enabledConfig,
            filePath: path.join(makeTempDir(), "first.js"),
            logger: {},
            pluginId: "first",
          }),
          await scanFileInstallSourceRuntime({
            config: disabledConfig,
            filePath: path.join(makeTempDir(), "second.js"),
            logger: {},
            pluginId: "second",
          }),
        ];
      },
    );

    expect(enabledResult?.blocked?.reason).toBe("blocked staged target first");
    expect(disabledResult).toBeUndefined();
  });

  it("filters an active scanner that the current restrictive allowlist excludes", async () => {
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
    const restrictedConfig = {
      agents: { defaults: { workspace: workspaceDir } },
      plugins: {
        allow: ["other"],
        entries: {
          other: { enabled: true },
        },
      },
    };

    const result = await withEnvAsync(
      {
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_STATE_DIR: stateDir,
      },
      async () => {
        ensurePluginRegistryLoaded({
          config: enabledConfig,
          workspaceDir,
          onlyPluginIds: [scanner.id],
        });
        return await scanFileInstallSourceRuntime({
          config: restrictedConfig,
          filePath: path.join(makeTempDir(), "payload.js"),
          logger: {},
          pluginId: "payload",
        });
      },
    );

    expect(result).toBeUndefined();
  });
});
