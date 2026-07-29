import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import {
  getGlobalHookRunnerMock,
  loadIsolatedPluginRegistryMock,
  loadPluginRegistrySnapshotMock,
  readPersistedInstalledPluginIndexSyncMock,
  resetInstallSecurityScanRuntimeMocks,
  resolveManifestActivationPlanMock,
  runInstallPolicyMock,
  useIsolatedSdkBeforeInstallHook,
} from "./install-security-scan.runtime.test-support.js";
const tempDirs = useAutoCleanupTempDirTracker(afterEach);

const { scanFileInstallSourceRuntime } = await import("./install-security-scan.runtime.js");

function scanPayload(config: Parameters<typeof scanFileInstallSourceRuntime>[0]["config"] = {}) {
  return scanFileInstallSourceRuntime({
    config,
    filePath: "/tmp/payload.js",
    logger: {},
    pluginId: "payload",
  });
}

type PersistedScanner = {
  compat: string[];
  enabled?: boolean;
  manifestPath?: string;
  origin: "config" | "global";
  packageJson?: { hash: string; path: string };
  pluginId: string;
  rootDir?: string;
  startup: { activationHooks?: string[] };
};

function persistScanner(overrides: Partial<PersistedScanner> = {}) {
  readPersistedInstalledPluginIndexSyncMock.mockReturnValue({
    plugins: [
      {
        compat: ["activation-capability-hint"],
        origin: "global",
        pluginId: "scanner",
        startup: { activationHooks: ["before_install"] },
        ...overrides,
      },
    ],
  });
}

beforeEach(() => {
  resetInstallSecurityScanRuntimeMocks();
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
    persistScanner({
      manifestPath: `${rootDir}/openclaw.plugin.json`,
      packageJson: {
        hash: "package-json-hash",
        path: "package.json",
      },
      pluginId: "canonical-scanner",
      rootDir,
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [],
      pluginIds: [],
      trigger: { kind: "hook", hook: "before_install" },
    });

    const result = await scanPayload({
      plugins: {
        entries: {
          "canonical-scanner": { enabled: true },
        },
      },
    });

    expect(result?.blocked?.reason).toContain("invalid package install metadata");
    expect(resolveManifestActivationPlanMock).toHaveBeenCalledWith(
      expect.objectContaining({
        onlyPluginIds: ["canonical-scanner"],
      }),
    );
  });

  it.each([
    {
      name: "persisted config-path scanner root disappears",
      arrange: () => {
        const rootDir = "/plugins/missing-scanner";
        return {
          configuredPath: rootDir,
          message: "plugin path not found",
          rootDir,
        };
      },
    },
    {
      name: "configured scanner container disappears",
      arrange: () => {
        const configuredPath = "/plugins/scanners";
        return {
          configuredPath,
          message: `plugin path not found: ${configuredPath}`,
          rootDir: `${configuredPath}/gate`,
        };
      },
    },
    {
      name: "configured scanner symlink becomes dangling",
      arrange: () => {
        const tempDir = tempDirs.make("openclaw-scanner-link-");
        const containerTarget = path.join(tempDir, "scanner-target");
        const configuredPath = path.join(tempDir, "configured-scanners");
        fs.mkdirSync(containerTarget);
        fs.symlinkSync(containerTarget, configuredPath);
        fs.rmSync(containerTarget, { recursive: true });
        return {
          configuredPath,
          message: `plugin path not found: ${configuredPath}`,
          rootDir: path.join(containerTarget, "gate"),
        };
      },
    },
  ])("fails closed when $name", async ({ arrange }) => {
    const { configuredPath, message, rootDir } = arrange();
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [{ level: "error", message, source: configuredPath }],
      plugins: [],
    });
    persistScanner({
      enabled: true,
      manifestPath: path.join(rootDir, "openclaw.plugin.json"),
      origin: "config",
      rootDir,
    });

    const result = await scanPayload({
      plugins: { load: { paths: [configuredPath] } },
    });

    expect(result?.blocked).toEqual({
      code: "security_scan_failed",
      reason: `Installation blocked because before_install hook failed: hook provider manifest discovery failed: ${message}`,
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
    persistScanner({
      enabled: true,
      manifestPath: `${rootDir}/openclaw.plugin.json`,
      origin: "config",
      rootDir,
    });

    await expect(scanPayload()).resolves.toBeUndefined();

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
    persistScanner({
      enabled: true,
      manifestPath: `${persistedRoot}/openclaw.plugin.json`,
      rootDir: persistedRoot,
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
      scanPayload({
        plugins: {
          allow: ["scanner"],
          load: { paths: [overrideRoot] },
        },
      }),
    ).resolves.toBeUndefined();

    expect(loadIsolatedPluginRegistryMock).toHaveBeenCalledWith(
      expect.objectContaining({
        onlyPluginIds: ["scanner"],
      }),
    );
  });

  it.each([
    {
      name: "current config disables it",
      origin: "global" as const,
      config: {
        plugins: {
          entries: {
            other: { enabled: true },
            scanner: { enabled: false },
          },
        },
      },
    },
    {
      name: "a restrictive allowlist excludes it",
      origin: "config" as const,
      config: {
        plugins: {
          allow: ["other"],
          entries: {
            other: { enabled: true },
            scanner: { enabled: true },
          },
        },
      },
    },
  ])("does not recover a malformed scanner when $name", async ({ config, origin }) => {
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
    persistScanner({
      manifestPath,
      origin,
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

    await expect(scanPayload(config)).resolves.toBeUndefined();

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
      scanPayload({
        plugins: {
          entries: {
            "broken-provider": { enabled: true },
            scanner: { enabled: true },
          },
        },
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

    await scanPayload(config);

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

  it.each([
    {
      name: "discovery skips a persisted scanner",
      message:
        "plugin requires plugin API >=2026.8.1, but this host is 2026.7.2; skipping discovery",
      compat: ["activation-capability-hint"],
      startup: { activationHooks: ["before_install"] },
    },
    {
      name: "legacy scanner metadata lacks hook fields",
      message: "invalid package plugin API metadata; skipping discovery",
      compat: [],
      startup: {},
    },
  ])("fails closed when $name", async ({ compat, message, startup }) => {
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "warn",
          message,
          pluginId: "scanner",
        },
      ],
      plugins: [],
    });
    persistScanner({
      compat,
      startup,
    });

    const result = await scanPayload({
      plugins: {
        entries: {
          scanner: { enabled: true },
        },
      },
    });

    expect(result?.blocked).toEqual({
      code: "security_scan_failed",
      reason: expect.stringContaining(message),
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
