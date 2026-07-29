import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";

const runInstallPolicyMock = vi.fn();
const findBlockedManifestDependenciesMock = vi.fn();
const findBlockedNodeModulesDirectoryMock = vi.fn();
const findBlockedNodeModulesFileAliasMock = vi.fn();
const findBlockedPackageDirectoryInPathMock = vi.fn();
const findBlockedPackageFileAliasInPathMock = vi.fn();
const getGlobalHookRunnerMock = vi.fn();
const getIsolatedGlobalHookRunnerRegistryMock = vi.fn();
const collectLivePluginRegistriesMock = vi.fn();
const getPluginRegistryWorkspaceDirMock = vi.fn();
const createHookRunnerMock = vi.fn();
const resolveManifestActivationPlanMock = vi.fn();
const loadPluginRegistrySnapshotMock = vi.fn();
const loadIsolatedPluginRegistryMock = vi.fn();
const loadInstalledPluginIndexInstallRecordsSyncMock = vi.fn();
const readPersistedInstalledPluginIndexSyncMock = vi.fn();
const getRuntimeConfigMock = vi.fn();
const tempDirs = useAutoCleanupTempDirTracker(afterEach);

vi.mock("../config/config.js", () => ({
  getRuntimeConfig: () => getRuntimeConfigMock(),
}));

vi.mock("../security/install-policy.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../security/install-policy.js")>();
  return {
    ...actual,
    runInstallPolicy: (...args: unknown[]) => runInstallPolicyMock(...args),
  };
});

vi.mock("./dependency-denylist.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./dependency-denylist.js")>();
  return {
    ...actual,
    findBlockedManifestDependencies: (...args: unknown[]) =>
      findBlockedManifestDependenciesMock(...args),
    findBlockedNodeModulesDirectory: (...args: unknown[]) =>
      findBlockedNodeModulesDirectoryMock(...args),
    findBlockedNodeModulesFileAlias: (...args: unknown[]) =>
      findBlockedNodeModulesFileAliasMock(...args),
    findBlockedPackageDirectoryInPath: (...args: unknown[]) =>
      findBlockedPackageDirectoryInPathMock(...args),
    findBlockedPackageFileAliasInPath: (...args: unknown[]) =>
      findBlockedPackageFileAliasInPathMock(...args),
  };
});

vi.mock("./hook-runner-global-state.js", () => ({
  getIsolatedGlobalHookRunnerRegistry: () => getIsolatedGlobalHookRunnerRegistryMock(),
}));

vi.mock("./runtime.js", () => ({
  collectLivePluginRegistries: () => collectLivePluginRegistriesMock(),
  getPluginRegistryWorkspaceDir: (...args: unknown[]) => getPluginRegistryWorkspaceDirMock(...args),
}));

vi.mock("./hooks.js", () => ({
  createHookRunner: (...args: unknown[]) => createHookRunnerMock(...args),
}));

vi.mock("./activation-planner.js", () => ({
  resolveManifestActivationPlan: (...args: unknown[]) => resolveManifestActivationPlanMock(...args),
}));

vi.mock("./plugin-registry-snapshot.js", () => ({
  loadPluginRegistrySnapshot: (...args: unknown[]) => loadPluginRegistrySnapshotMock(...args),
}));

vi.mock("./installed-plugin-index-store.js", () => ({
  readPersistedInstalledPluginIndexSync: (...args: unknown[]) =>
    readPersistedInstalledPluginIndexSyncMock(...args),
}));

vi.mock("./installed-plugin-index-record-reader.js", () => ({
  loadInstalledPluginIndexInstallRecordsSync: (...args: unknown[]) =>
    loadInstalledPluginIndexInstallRecordsSyncMock(...args),
}));

vi.mock("./runtime/runtime-registry-loader.js", () => ({
  loadIsolatedPluginRegistry: (...args: unknown[]) => loadIsolatedPluginRegistryMock(...args),
}));

const { scanFileInstallSourceRuntime } = await import("./install-security-scan.runtime.js");

function useIsolatedSdkBeforeInstallHook(pluginId = "sdk-install-gate") {
  getIsolatedGlobalHookRunnerRegistryMock.mockReturnValue({
    hooks: [],
    typedHooks: [
      {
        handler: vi.fn(),
        hookName: "before_install",
        pluginId,
        priority: 0,
        source: "sdk",
      },
    ],
    plugins: [{ id: pluginId, status: "loaded" }],
  });
}

beforeEach(() => {
  getRuntimeConfigMock.mockReset();
  getRuntimeConfigMock.mockReturnValue({});
  runInstallPolicyMock.mockReset();
  findBlockedManifestDependenciesMock.mockReset();
  findBlockedNodeModulesDirectoryMock.mockReset();
  findBlockedNodeModulesFileAliasMock.mockReset();
  findBlockedPackageDirectoryInPathMock.mockReset();
  findBlockedPackageFileAliasInPathMock.mockReset();
  getGlobalHookRunnerMock.mockReset();
  getIsolatedGlobalHookRunnerRegistryMock.mockReset();
  getIsolatedGlobalHookRunnerRegistryMock.mockReturnValue(null);
  collectLivePluginRegistriesMock.mockReset();
  collectLivePluginRegistriesMock.mockReturnValue([]);
  getPluginRegistryWorkspaceDirMock.mockReset();
  getPluginRegistryWorkspaceDirMock.mockReturnValue(undefined);
  createHookRunnerMock.mockReset();
  createHookRunnerMock.mockImplementation(() => getGlobalHookRunnerMock());
  resolveManifestActivationPlanMock.mockReset();
  resolveManifestActivationPlanMock.mockReturnValue({
    diagnostics: [],
    entries: [],
    pluginIds: [],
    trigger: { kind: "hook", hook: "before_install" },
  });
  loadPluginRegistrySnapshotMock.mockReset();
  loadPluginRegistrySnapshotMock.mockReturnValue({ diagnostics: [], plugins: [] });
  loadIsolatedPluginRegistryMock.mockReset();
  loadInstalledPluginIndexInstallRecordsSyncMock.mockReset();
  loadInstalledPluginIndexInstallRecordsSyncMock.mockReturnValue({});
  loadIsolatedPluginRegistryMock.mockImplementation(
    (options: { onlyPluginIds?: readonly string[] } = {}) => ({
      hooks: [],
      plugins: (options.onlyPluginIds ?? []).map((id) => ({ id, status: "loaded" })),
      typedHooks: (options.onlyPluginIds ?? []).map((pluginId) => ({
        handler: vi.fn(),
        hookName: "before_install",
        pluginId,
        priority: 0,
        source: "test",
      })),
    }),
  );
  readPersistedInstalledPluginIndexSyncMock.mockReset();
  readPersistedInstalledPluginIndexSyncMock.mockReturnValue(null);
});

describe("legacy install scan recovery and persistence", () => {
  it("recovers a scanner when package metadata discovery fails", async () => {
    const rootDir = "/plugins/scanner";
    const packageJsonPath = `${rootDir}/package.json`;
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "invalid package install metadata",
          pluginId: "package-id-hint",
          source: packageJsonPath,
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          manifestPath: `${rootDir}/openclaw.plugin.json`,
          origin: "global",
          packageJson: {
            hash: "package-json-hash",
            path: "package.json",
          },
          pluginId: "canonical-scanner",
          rootDir,
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [],
      pluginIds: [],
      trigger: { kind: "hook", hook: "before_install" },
    });

    const result = await scanFileInstallSourceRuntime({
      config: {
        plugins: {
          entries: {
            "canonical-scanner": { enabled: true },
          },
        },
      },
      filePath: "/tmp/payload.js",
      logger: {},
      pluginId: "payload",
    });

    expect(result?.blocked?.reason).toContain("invalid package install metadata");
    expect(resolveManifestActivationPlanMock).toHaveBeenCalledWith(
      expect.objectContaining({
        onlyPluginIds: ["canonical-scanner"],
      }),
    );
  });

  it("fails closed when a persisted config-path scanner root disappears", async () => {
    const rootDir = "/plugins/missing-scanner";
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "plugin path not found",
          source: rootDir,
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          enabled: true,
          manifestPath: `${rootDir}/openclaw.plugin.json`,
          origin: "config",
          pluginId: "scanner",
          rootDir,
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [],
      pluginIds: [],
      trigger: { kind: "hook", hook: "before_install" },
    });

    const result = await scanFileInstallSourceRuntime({
      config: {
        plugins: {
          load: { paths: [rootDir] },
        },
      },
      filePath: "/tmp/payload.js",
      logger: {},
      pluginId: "payload",
    });

    expect(result).toEqual({
      blocked: {
        code: "security_scan_failed",
        reason:
          "Installation blocked because before_install hook failed: hook provider manifest discovery failed: plugin path not found",
      },
    });
    expect(loadIsolatedPluginRegistryMock).not.toHaveBeenCalled();
  });

  it("fails closed when a configured scanner container disappears", async () => {
    const containerDir = "/plugins/scanners";
    const rootDir = `${containerDir}/gate`;
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: `plugin path not found: ${containerDir}`,
          source: containerDir,
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          enabled: true,
          manifestPath: `${rootDir}/openclaw.plugin.json`,
          origin: "config",
          pluginId: "scanner",
          rootDir,
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });

    const result = await scanFileInstallSourceRuntime({
      config: {
        plugins: {
          load: { paths: [containerDir] },
        },
      },
      filePath: "/tmp/payload.js",
      logger: {},
      pluginId: "payload",
    });

    expect(result?.blocked).toEqual({
      code: "security_scan_failed",
      reason: expect.stringContaining(`plugin path not found: ${containerDir}`),
    });
    expect(loadIsolatedPluginRegistryMock).not.toHaveBeenCalled();
  });

  it("fails closed when a configured scanner symlink becomes dangling", async () => {
    const tempDir = tempDirs.make("openclaw-scanner-link-");
    const containerTarget = path.join(tempDir, "scanner-target");
    const configuredLink = path.join(tempDir, "configured-scanners");
    const rootDir = path.join(containerTarget, "gate");
    fs.mkdirSync(containerTarget);
    fs.symlinkSync(containerTarget, configuredLink);
    fs.rmSync(containerTarget, { recursive: true });

    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: `plugin path not found: ${configuredLink}`,
          source: configuredLink,
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          enabled: true,
          manifestPath: path.join(rootDir, "openclaw.plugin.json"),
          origin: "config",
          pluginId: "scanner",
          rootDir,
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });

    const result = await scanFileInstallSourceRuntime({
      config: {
        plugins: {
          load: { paths: [configuredLink] },
        },
      },
      filePath: "/tmp/payload.js",
      logger: {},
      pluginId: "payload",
    });

    expect(result?.blocked).toEqual({
      code: "security_scan_failed",
      reason: expect.stringContaining(`plugin path not found: ${configuredLink}`),
    });
    expect(loadIsolatedPluginRegistryMock).not.toHaveBeenCalled();
  });

  it("revokes persisted config-path scanner trust after its load path is removed", async () => {
    const rootDir = "/plugins/stale-scanner";
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "scanner manifest could not be parsed",
          pluginId: "scanner",
          source: `${rootDir}/openclaw.plugin.json`,
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          enabled: true,
          manifestPath: `${rootDir}/openclaw.plugin.json`,
          origin: "config",
          pluginId: "scanner",
          rootDir,
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });

    await expect(
      scanFileInstallSourceRuntime({
        config: {},
        filePath: "/tmp/payload.js",
        logger: {},
        pluginId: "payload",
      }),
    ).resolves.toBeUndefined();

    expect(resolveManifestActivationPlanMock).not.toHaveBeenCalled();
    expect(loadIsolatedPluginRegistryMock).not.toHaveBeenCalled();
  });

  it("ignores a broken persisted scanner source shadowed by a valid override", async () => {
    const persistedRoot = "/plugins/installed-scanner";
    const overrideRoot = "/plugins/config-scanner";
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "installed scanner manifest could not be parsed",
          pluginId: "scanner",
          source: `${persistedRoot}/openclaw.plugin.json`,
        },
      ],
      plugins: [
        {
          enabled: true,
          manifestPath: `${overrideRoot}/openclaw.plugin.json`,
          origin: "config",
          pluginId: "scanner",
          rootDir: overrideRoot,
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          enabled: true,
          manifestPath: `${persistedRoot}/openclaw.plugin.json`,
          origin: "global",
          pluginId: "scanner",
          rootDir: persistedRoot,
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [
        {
          origin: "config",
          pluginId: "scanner",
          reasons: ["activation-hook-hint"],
        },
      ],
      pluginIds: ["scanner"],
      trigger: { kind: "hook", hook: "before_install" },
    });

    await expect(
      scanFileInstallSourceRuntime({
        config: {
          plugins: {
            allow: ["scanner"],
            load: { paths: [overrideRoot] },
          },
        },
        filePath: "/tmp/payload.js",
        logger: {},
        pluginId: "payload",
      }),
    ).resolves.toBeUndefined();

    expect(loadIsolatedPluginRegistryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        onlyPluginIds: ["scanner"],
      }),
    );
  });

  it("does not recover a malformed scanner after current config disables it", async () => {
    const manifestPath = "/plugins/scanner/openclaw.plugin.json";
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "scanner manifest could not be parsed",
          pluginId: "scanner",
          source: manifestPath,
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          manifestPath,
          origin: "global",
          pluginId: "scanner",
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "scanner manifest could not be parsed",
          pluginId: "scanner",
        },
      ],
      entries: [],
      pluginIds: [],
      trigger: { kind: "hook", hook: "before_install" },
    });
    getGlobalHookRunnerMock.mockReturnValue(null);

    await expect(
      scanFileInstallSourceRuntime({
        config: {
          plugins: {
            entries: {
              other: { enabled: true },
              scanner: { enabled: false },
            },
          },
        },
        filePath: "/tmp/payload.js",
        logger: {},
        pluginId: "payload",
      }),
    ).resolves.toBeUndefined();

    expect(loadIsolatedPluginRegistryMock).not.toHaveBeenCalled();
  });

  it("does not recover a config-path scanner excluded by a restrictive allowlist", async () => {
    const manifestPath = "/plugins/scanner/openclaw.plugin.json";
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "scanner manifest could not be parsed",
          pluginId: "scanner",
          source: manifestPath,
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          manifestPath,
          origin: "config",
          pluginId: "scanner",
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "scanner manifest could not be parsed",
          pluginId: "scanner",
        },
      ],
      entries: [],
      pluginIds: [],
      trigger: { kind: "hook", hook: "before_install" },
    });
    getGlobalHookRunnerMock.mockReturnValue(null);

    await expect(
      scanFileInstallSourceRuntime({
        config: {
          plugins: {
            allow: ["other"],
            entries: {
              other: { enabled: true },
            },
          },
        },
        filePath: "/tmp/payload.js",
        logger: {},
        pluginId: "payload",
      }),
    ).resolves.toBeUndefined();

    expect(loadIsolatedPluginRegistryMock).not.toHaveBeenCalled();
  });

  it("ignores unowned manifest errors when another plugin provides hooks", async () => {
    loadPluginRegistrySnapshotMock.mockReturnValue({
      plugins: [
        {
          enabled: true,
          pluginId: "scanner",
          startup: { activationHooks: ["before_install"] },
        },
        {
          enabled: true,
          pluginId: "broken-provider",
          startup: { activationCapabilities: ["provider"] },
        },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "provider manifest could not be parsed",
        },
      ],
      entries: [
        {
          pluginId: "scanner",
          origin: "global",
          reasons: ["activation-hook-hint"],
        },
      ],
      pluginIds: ["scanner"],
      trigger: { kind: "hook", hook: "before_install" },
    });

    await expect(
      scanFileInstallSourceRuntime({
        config: {
          plugins: {
            entries: {
              "broken-provider": { enabled: true },
              scanner: { enabled: true },
            },
          },
        },
        filePath: "/tmp/payload.js",
        logger: {},
        pluginId: "payload",
      }),
    ).resolves.toBeUndefined();

    expect(loadIsolatedPluginRegistryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        onlyPluginIds: ["scanner"],
      }),
    );
  });

  it("preserves canonical mixed-case ids and includes config load-path hook providers", async () => {
    const config = {
      plugins: {
        allow: ["local-scanner", "scanner-x"],
        load: { paths: ["/tmp/local-scanner"] },
      },
    };
    loadPluginRegistrySnapshotMock.mockReturnValue({
      plugins: [
        { enabled: true, origin: "global", pluginId: "Scanner-X" },
        { enabled: true, origin: "config", pluginId: "Local-Scanner" },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [
        {
          pluginId: "Local-Scanner",
          origin: "config",
          reasons: ["activation-hook-hint"],
        },
        {
          pluginId: "Scanner-X",
          origin: "global",
          reasons: ["activation-hook-hint"],
        },
      ],
      pluginIds: ["Local-Scanner", "Scanner-X"],
      trigger: { kind: "hook", hook: "before_install" },
    });
    const hasHooks = vi.fn().mockReturnValue(true);
    const runBeforeInstall = vi.fn().mockResolvedValue(undefined);
    getGlobalHookRunnerMock.mockReturnValue({ hasHooks, runBeforeInstall });

    await scanFileInstallSourceRuntime({
      config,
      filePath: "/tmp/payload.js",
      logger: {},
      pluginId: "payload",
    });

    expect(resolveManifestActivationPlanMock).toHaveBeenCalledWith(
      expect.objectContaining({
        onlyPluginIds: ["Local-Scanner", "Scanner-X"],
      }),
    );
    expect(loadIsolatedPluginRegistryMock).toHaveBeenCalledWith({
      config,
      index: {
        plugins: [
          { enabled: true, origin: "global", pluginId: "Scanner-X" },
          { enabled: true, origin: "config", pluginId: "Local-Scanner" },
        ],
      },
      workspaceDir: expect.any(String),
      onlyPluginIds: ["Local-Scanner", "Scanner-X"],
    });
  });

  it("fails closed when discovery skips a persisted scanner", async () => {
    const compatibilityMessage =
      "plugin requires plugin API >=2026.8.1, but this host is 2026.7.2; skipping discovery";
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "warn",
          message: compatibilityMessage,
          pluginId: "scanner",
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: ["activation-capability-hint"],
          origin: "global",
          pluginId: "scanner",
          startup: { activationHooks: ["before_install"] },
        },
      ],
    });

    const result = await scanFileInstallSourceRuntime({
      config: {
        plugins: {
          entries: {
            scanner: { enabled: true },
          },
        },
      },
      filePath: "/tmp/payload.js",
      logger: {},
      pluginId: "payload",
    });

    expect(result?.blocked).toEqual({
      code: "security_scan_failed",
      reason: expect.stringContaining(compatibilityMessage),
    });
  });

  it("fails closed on discovery errors when legacy scanner metadata lacks hook fields", async () => {
    const discoveryMessage = "invalid package plugin API metadata; skipping discovery";
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "warn",
          message: discoveryMessage,
          pluginId: "scanner",
        },
      ],
      plugins: [],
    });
    readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
      plugins: [
        {
          compat: [],
          origin: "global",
          pluginId: "scanner",
          startup: {},
        },
      ],
    });

    const result = await scanFileInstallSourceRuntime({
      config: {
        plugins: {
          entries: {
            scanner: { enabled: true },
          },
        },
      },
      filePath: "/tmp/payload.js",
      logger: {},
      pluginId: "payload",
    });

    expect(result?.blocked).toEqual({
      code: "security_scan_failed",
      reason: expect.stringContaining(discoveryMessage),
    });
  });

  it("preserves policy and hook metadata for published lazy install chunks", async () => {
    const warnings: string[] = [];
    const hasHooks = vi.fn().mockReturnValue(true);
    const runBeforeInstall = vi.fn().mockResolvedValue(undefined);
    getGlobalHookRunnerMock.mockReturnValue({ hasHooks, runBeforeInstall });
    useIsolatedSdkBeforeInstallHook();
    runInstallPolicyMock.mockResolvedValueOnce({
      findings: [
        {
          ruleId: "registry-review",
          severity: "warn",
          message: "Registry requires review.",
        },
      ],
    });

    const result = await scanFileInstallSourceRuntime({
      filePath: "/tmp/payload.js",
      logger: { warn: (message) => warnings.push(message) },
      mode: "update",
      pluginId: "payload",
      requestedSpecifier: "./payload.js",
    });

    expect(result).toBeUndefined();
    expect(warnings).toEqual(["Install policy: Registry requires review."]);
    expect(runInstallPolicyMock).toHaveBeenCalledWith({
      config: undefined,
      logger: expect.any(Object),
      request: {
        targetName: "payload",
        targetType: "plugin",
        sourcePath: "/tmp/payload.js",
        sourcePathKind: "file",
        source: { kind: "file", authority: "user", mutable: true, network: false },
        origin: { type: "plugin-file" },
        request: {
          kind: "plugin-file",
          mode: "update",
          requestedSpecifier: "./payload.js",
        },
        plugin: {
          contentType: "file",
          pluginId: "payload",
          extensions: ["payload.js"],
        },
      },
    });
    expect(hasHooks).toHaveBeenCalledWith("before_install");
    expect(runBeforeInstall).toHaveBeenCalledWith(
      {
        targetName: "payload",
        targetType: "plugin",
        origin: "plugin-file",
        sourcePath: "/tmp/payload.js",
        sourcePathKind: "file",
        request: {
          kind: "plugin-file",
          mode: "update",
          requestedSpecifier: "./payload.js",
        },
        builtinScan: {
          status: "ok",
          scannedFiles: 0,
          critical: 0,
          warn: 0,
          info: 0,
          findings: [],
        },
        plugin: {
          contentType: "file",
          pluginId: "payload",
          extensions: ["payload.js"],
        },
      },
      {
        origin: "plugin-file",
        targetType: "plugin",
        requestKind: "plugin-file",
      },
    );
  });

  it("returns operator policy blocks before invoking hooks", async () => {
    runInstallPolicyMock.mockResolvedValueOnce({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked by operator policy",
      },
    });

    const result = await scanFileInstallSourceRuntime({
      filePath: "/tmp/payload.js",
      logger: {},
      pluginId: "payload",
    });

    expect(result).toEqual({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked by operator policy",
      },
    });
    expect(getGlobalHookRunnerMock).not.toHaveBeenCalled();
  });
});
