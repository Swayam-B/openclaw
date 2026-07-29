import fs from "node:fs";
import path from "node:path";
import { afterAll, afterEach, describe, expect, it } from "vitest";
import {
  clearContextEnginesForOwner,
  getContextEngineRegistration,
} from "../context-engine/registry.js";
import { withEnvAsync } from "../test-utils/env.js";
import { clearCompactionProviders, getCompactionProvider } from "./compaction-provider.js";
import { resetGlobalHookRunner } from "./hook-runner-global.js";
import {
  evaluateSkillInstallPolicyRuntime,
  scanBundleInstallSourceRuntime,
  scanFileInstallSourceRuntime,
} from "./install-security-scan.runtime.js";
import { refreshPersistedInstalledPluginIndex } from "./installed-plugin-index-store.js";
import {
  cleanupPluginLoaderFixturesForTest,
  makeTempDir,
  resetPluginLoaderTestStateForTest,
  useNoBundledPlugins,
  writePlugin,
} from "./loader.test-fixtures.js";
import { loadPluginRegistrySnapshot } from "./plugin-registry-snapshot.js";
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

function writeSideEffectingBeforeInstallBlocker(id: string, compactionProviderId: string) {
  const plugin = writePlugin({
    id,
    filename: `${id}.cjs`,
    body: `module.exports = { id: ${JSON.stringify(id)}, register(api) {
      api.registerCompactionProvider({
        id: ${JSON.stringify(compactionProviderId)},
        label: "install scan poison",
        summarize: async () => ({ summary: "poison" }),
      });
      api.on("before_install", () => ({
        block: true,
        blockReason: "blocked without global side effects",
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
  clearCompactionProviders();
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

  it("exposes only typed hooks during transient install scans", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const compactionProviderId = "install-scan-poison";
    const scanner = writeSideEffectingBeforeInstallBlocker(
      "side-effecting-install-scanner",
      compactionProviderId,
    );

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

    expect(result?.blocked?.reason).toBe("blocked without global side effects");
    expect(getCompactionProvider(compactionProviderId)).toBeUndefined();
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

  it("does not accept a legacy internal hook as a before_install provider", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const scanner = writePlugin({
      id: "legacy-internal-hook-scanner",
      filename: "legacy-internal-hook-scanner.cjs",
      body: `module.exports = { id: "legacy-internal-hook-scanner", register(api) {
        api.registerHook("before_install", () => {}, { name: "legacy-before-install" });
      } };`,
    });
    const manifestPath = path.join(scanner.dir, "openclaw.plugin.json");
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    manifest.activation = { onHooks: ["before_install"] };
    fs.writeFileSync(manifestPath, JSON.stringify(manifest), "utf8");

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
        "hook providers did not register before_install in install-scan mode: legacy-internal-hook-scanner",
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

  it("does not reuse another workspace's persisted registry for an install scan", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const firstWorkspaceDir = makeTempDir();
    const targetWorkspaceDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker(
      "target-workspace-scanner",
      path.join(targetWorkspaceDir, ".openclaw", "extensions", "target-workspace-scanner"),
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
        await refreshPersistedInstalledPluginIndex({
          reason: "manual",
          config,
          workspaceDir: firstWorkspaceDir,
          stateDir,
          env: process.env,
        });
        resetPluginLoaderTestStateForTest();
        const targetSnapshot = loadPluginRegistrySnapshot({
          config,
          workspaceDir: targetWorkspaceDir,
          preferPersisted: false,
        });
        expect(targetSnapshot.plugins.map((plugin) => plugin.pluginId)).toContain(scanner.id);
        return await evaluateSkillInstallPolicyRuntime({
          config,
          workspaceDir: targetWorkspaceDir,
          installId: "node",
          logger: {},
          origin: { type: "workspace" },
          skillName: "payload",
          sourceDir: makeTempDir(),
        });
      },
    );

    expect(result?.blocked?.reason).toBe("blocked staged target payload");
  });

  it("derives managed npm scanners from install records instead of persisted metadata", async () => {
    useNoBundledPlugins();
    const stateDir = makeTempDir();
    const workspaceDir = makeTempDir();
    const scanner = writeBeforeInstallBlocker(
      "managed-install-scanner",
      path.join(
        stateDir,
        "npm",
        "projects",
        "managed-install-scanner",
        "node_modules",
        "managed-install-scanner",
      ),
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
        await refreshPersistedInstalledPluginIndex({
          reason: "source-changed",
          config,
          stateDir,
          env: process.env,
          installRecords: {
            [scanner.id]: {
              source: "npm",
              spec: `${scanner.id}@1.0.0`,
              installPath: scanner.dir,
            },
          },
        });
        resetPluginLoaderTestStateForTest();
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

    expect(result?.blocked?.reason).toBe("blocked staged target payload");
  });
});
