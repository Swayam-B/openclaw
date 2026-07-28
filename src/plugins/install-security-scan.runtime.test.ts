import { beforeEach, describe, expect, it, vi } from "vitest";

const runInstallPolicyMock = vi.fn();
const findBlockedManifestDependenciesMock = vi.fn();
const findBlockedNodeModulesDirectoryMock = vi.fn();
const findBlockedNodeModulesFileAliasMock = vi.fn();
const findBlockedPackageDirectoryInPathMock = vi.fn();
const findBlockedPackageFileAliasInPathMock = vi.fn();
const getGlobalHookRunnerMock = vi.fn();
const getGlobalHookRunnerRegistryMock = vi.fn();
const createHookRunnerMock = vi.fn();
const resolveManifestActivationPlanMock = vi.fn();
const loadPluginRegistrySnapshotMock = vi.fn();
const loadIsolatedPluginRegistryMock = vi.fn();
const readPersistedInstalledPluginIndexSyncMock = vi.fn();

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

vi.mock("./hook-runner-global.js", () => ({
  getGlobalHookRunner: () => getGlobalHookRunnerMock(),
}));

vi.mock("./hook-runner-global-state.js", () => ({
  getGlobalHookRunnerRegistry: () => getGlobalHookRunnerRegistryMock(),
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

vi.mock("./runtime/runtime-registry-loader.js", () => ({
  loadIsolatedPluginRegistry: (...args: unknown[]) => loadIsolatedPluginRegistryMock(...args),
}));

const {
  evaluateSkillInstallPolicyRuntime,
  preflightPluginNpmInstallPolicyRuntime,
  scanBundleInstallSourceRuntime,
  scanFileInstallSourceRuntime,
  scanPackageInstallSourceRuntime,
} = await import("./install-security-scan.runtime.js");

function expectBuiltinInstallFrictionBypassed() {
  expect(runInstallPolicyMock).toHaveBeenCalledTimes(1);
  expect(findBlockedManifestDependenciesMock).not.toHaveBeenCalled();
  expect(findBlockedNodeModulesDirectoryMock).not.toHaveBeenCalled();
  expect(findBlockedNodeModulesFileAliasMock).not.toHaveBeenCalled();
  expect(findBlockedPackageDirectoryInPathMock).not.toHaveBeenCalled();
  expect(findBlockedPackageFileAliasInPathMock).not.toHaveBeenCalled();
}

beforeEach(() => {
  runInstallPolicyMock.mockReset();
  findBlockedManifestDependenciesMock.mockReset();
  findBlockedNodeModulesDirectoryMock.mockReset();
  findBlockedNodeModulesFileAliasMock.mockReset();
  findBlockedPackageDirectoryInPathMock.mockReset();
  findBlockedPackageFileAliasInPathMock.mockReset();
  getGlobalHookRunnerMock.mockReset();
  getGlobalHookRunnerRegistryMock.mockReset();
  getGlobalHookRunnerRegistryMock.mockReturnValue(null);
  createHookRunnerMock.mockReset();
  createHookRunnerMock.mockImplementation(() => getGlobalHookRunnerMock());
  resolveManifestActivationPlanMock.mockReset();
  resolveManifestActivationPlanMock.mockReturnValue({
    diagnostics: [],
    entries: [],
    pluginIds: [],
    trigger: { kind: "capability", capability: "hook" },
  });
  loadPluginRegistrySnapshotMock.mockReset();
  loadPluginRegistrySnapshotMock.mockReturnValue({ diagnostics: [], plugins: [] });
  loadIsolatedPluginRegistryMock.mockReset();
  loadIsolatedPluginRegistryMock.mockReturnValue({
    hooks: [],
    plugins: [],
    typedHooks: [],
  });
  readPersistedInstalledPluginIndexSyncMock.mockReset();
  readPersistedInstalledPluginIndexSyncMock.mockReturnValue(null);
});

describe("install security scan official bypass", () => {
  it("bypasses built-in friction but still runs hooks for bundled OpenClaw sources", async () => {
    const hasHooks = vi.fn().mockReturnValue(true);
    const runBeforeInstall = vi.fn().mockResolvedValue(undefined);
    getGlobalHookRunnerMock.mockReturnValue({ hasHooks, runBeforeInstall });

    const result = await scanBundleInstallSourceRuntime({
      logger: {},
      pluginId: "openclaw/kitchen-sink",
      sourceDir: "/tmp/openclaw-bundled-plugin",
      source: { kind: "bundled", authority: "openclaw", mutable: false, network: false },
    });

    expect(result).toBeUndefined();
    expectBuiltinInstallFrictionBypassed();
    expect(resolveManifestActivationPlanMock).not.toHaveBeenCalled();
    expect(runBeforeInstall).toHaveBeenCalledOnce();
  });

  it("bypasses built-in friction but still lets hooks block official ClawHub sources", async () => {
    const hasHooks = vi.fn().mockReturnValue(true);
    const runBeforeInstall = vi.fn().mockResolvedValue({
      block: true,
      blockReason: "scanner rejected source",
    });
    getGlobalHookRunnerMock.mockReturnValue({ hasHooks, runBeforeInstall });

    const result = await scanBundleInstallSourceRuntime({
      logger: {},
      pluginId: "@openclaw/matrix",
      sourceDir: "/tmp/openclaw-official-clawhub-plugin",
      source: { kind: "clawhub", authority: "official", mutable: false, network: true },
    });

    expect(result).toEqual({
      blocked: {
        code: "security_scan_blocked",
        reason: "scanner rejected source",
      },
    });
    expectBuiltinInstallFrictionBypassed();
  });

  it("bypasses built-in friction but still runs hooks for bundled OpenClaw skills", async () => {
    const hasHooks = vi.fn().mockReturnValue(true);
    const runBeforeInstall = vi.fn().mockResolvedValue(undefined);
    getGlobalHookRunnerMock.mockReturnValue({ hasHooks, runBeforeInstall });

    const result = await evaluateSkillInstallPolicyRuntime({
      workspaceDir: "/tmp/openclaw-workspace",
      installId: "node",
      logger: {},
      origin: {
        type: "openclaw-bundled",
        skillName: "peekaboo",
        installId: "node",
      },
      source: { kind: "bundled", authority: "openclaw", mutable: false, network: false },
      skillName: "peekaboo",
      sourceDir: "/tmp/openclaw-bundled-skill/peekaboo",
    });

    expect(result).toBeUndefined();
    expectBuiltinInstallFrictionBypassed();
    expect(runBeforeInstall).toHaveBeenCalledOnce();
  });

  it("bypasses built-in friction but still runs hooks for official package sources", async () => {
    const hasHooks = vi.fn().mockReturnValue(true);
    const runBeforeInstall = vi.fn().mockResolvedValue(undefined);
    getGlobalHookRunnerMock.mockReturnValue({ hasHooks, runBeforeInstall });

    const result = await scanPackageInstallSourceRuntime({
      extensions: ["index.js"],
      logger: {},
      packageDir: "/tmp/openclaw-official-package",
      pluginId: "matrix",
      source: { kind: "npm", authority: "official", mutable: false, network: true },
      trustedSourceLinkedOfficialInstall: true,
    });

    expect(result).toBeUndefined();
    expectBuiltinInstallFrictionBypassed();
    expect(runBeforeInstall).toHaveBeenCalledOnce();
  });

  it("runs only operator policy for official immutable npm sources", async () => {
    const result = await preflightPluginNpmInstallPolicyRuntime({
      logger: {},
      packageName: "@openclaw/matrix",
      requestedSpecifier: "@openclaw/matrix@latest",
      source: { kind: "npm", authority: "official", mutable: false, network: true },
      sourcePath: "/tmp/openclaw-official-npm",
      sourcePathKind: "directory",
    });

    expect(result).toBeUndefined();
    expectBuiltinInstallFrictionBypassed();
    expect(getGlobalHookRunnerMock).not.toHaveBeenCalled();
  });

  it("lets operator policy block official sources", async () => {
    runInstallPolicyMock.mockResolvedValueOnce({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked by operator policy",
      },
    });

    const result = await scanBundleInstallSourceRuntime({
      logger: {},
      pluginId: "@openclaw/matrix",
      sourceDir: "/tmp/openclaw-official-clawhub-plugin",
      source: { kind: "clawhub", authority: "official", mutable: false, network: true },
    });

    expect(result).toEqual({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked by operator policy",
      },
    });
    expectBuiltinInstallFrictionBypassed();
    expect(resolveManifestActivationPlanMock).not.toHaveBeenCalled();
    expect(getGlobalHookRunnerMock).not.toHaveBeenCalled();
  });

  it("still runs install policy for mutable workspace skill sources", async () => {
    runInstallPolicyMock.mockResolvedValueOnce({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked by operator policy",
      },
    });

    const result = await evaluateSkillInstallPolicyRuntime({
      workspaceDir: "/tmp/openclaw-workspace",
      installId: "node",
      logger: {},
      origin: {
        type: "workspace",
        skillName: "local-skill",
        installId: "node",
      },
      source: { kind: "workspace", authority: "user", mutable: true, network: false },
      skillName: "local-skill",
      sourceDir: "/tmp/local-skill",
    });

    expect(result).toEqual({
      blocked: {
        code: "security_scan_blocked",
        reason: "blocked by operator policy",
      },
    });
    expect(runInstallPolicyMock).toHaveBeenCalledTimes(1);
  });
});

describe("legacy file install scan compatibility", () => {
  it("loads every trusted hook-capability plugin before dispatch", async () => {
    const config = {
      plugins: {
        entries: {
          "scanner-a": { enabled: true },
          "scanner-b": { enabled: true },
        },
      },
    };
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [
        {
          pluginId: "scanner-a",
          origin: "global",
          reasons: ["activation-capability-hint"],
        },
        {
          pluginId: "scanner-b",
          origin: "global",
          reasons: ["activation-capability-hint"],
        },
      ],
      pluginIds: ["scanner-a", "scanner-b"],
      trigger: { kind: "capability", capability: "hook" },
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

    expect(resolveManifestActivationPlanMock).toHaveBeenCalledWith({
      config,
      workspaceDir: expect.any(String),
      onlyPluginIds: ["scanner-a", "scanner-b"],
      requireExplicitManifestOwnerTrust: true,
      trigger: {
        kind: "capability",
        capability: "hook",
      },
    });
    expect(loadIsolatedPluginRegistryMock).toHaveBeenCalledWith({
      config,
      workspaceDir: expect.any(String),
      onlyPluginIds: ["scanner-a", "scanner-b"],
    });
    expect(runBeforeInstall).toHaveBeenCalledOnce();
  });

  it("loads a lazy hook provider without replacing the active registry", async () => {
    const config = {
      plugins: {
        load: { paths: ["/tmp/command-plugin", "/tmp/scanner"] },
      },
    };
    loadPluginRegistrySnapshotMock.mockReturnValue({
      plugins: [
        { enabled: true, origin: "config", pluginId: "command-plugin" },
        { enabled: true, origin: "config", pluginId: "scanner" },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [
        {
          pluginId: "scanner",
          origin: "config",
          reasons: ["activation-capability-hint"],
        },
      ],
      pluginIds: ["scanner"],
      trigger: { kind: "capability", capability: "hook" },
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

    expect(loadIsolatedPluginRegistryMock).toHaveBeenCalledWith({
      config,
      workspaceDir: expect.any(String),
      onlyPluginIds: ["scanner"],
    });
  });

  it("does not treat bundle hook directories as before_install providers", async () => {
    const config = {
      plugins: {
        load: { paths: ["/tmp/hook-bundle"] },
      },
    };
    loadPluginRegistrySnapshotMock.mockReturnValue({
      plugins: [{ enabled: true, origin: "config", pluginId: "hook-bundle" }],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [
        {
          pluginId: "hook-bundle",
          origin: "config",
          reasons: ["manifest-hook-owner"],
        },
      ],
      pluginIds: ["hook-bundle"],
      trigger: { kind: "capability", capability: "hook" },
    });
    getGlobalHookRunnerMock.mockReturnValue(null);

    await expect(
      scanFileInstallSourceRuntime({
        config,
        filePath: "/tmp/payload.js",
        logger: {},
        pluginId: "payload",
      }),
    ).resolves.toBeUndefined();

    expect(loadIsolatedPluginRegistryMock).not.toHaveBeenCalled();
  });

  it("fails closed when a declared hook provider cannot load", async () => {
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [
        {
          pluginId: "scanner",
          origin: "global",
          reasons: ["activation-capability-hint"],
        },
      ],
      pluginIds: ["scanner"],
      trigger: { kind: "capability", capability: "hook" },
    });
    loadIsolatedPluginRegistryMock.mockImplementation(() => {
      throw new Error("scanner runtime unavailable");
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

    expect(result).toEqual({
      blocked: {
        code: "security_scan_failed",
        reason:
          "Installation blocked because before_install hook failed: scanner runtime unavailable",
      },
    });
    expect(getGlobalHookRunnerMock).not.toHaveBeenCalled();
  });

  it("fails closed when hook-provider manifest discovery reports an error", async () => {
    loadPluginRegistrySnapshotMock.mockReturnValue({
      plugins: [
        {
          enabled: true,
          pluginId: "scanner",
          startup: { activationCapabilities: ["hook"] },
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
      trigger: { kind: "capability", capability: "hook" },
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

    expect(result).toEqual({
      blocked: {
        code: "security_scan_failed",
        reason:
          "Installation blocked because before_install hook failed: hook provider manifest discovery failed: scanner manifest could not be parsed",
      },
    });
    expect(loadIsolatedPluginRegistryMock).not.toHaveBeenCalled();
    expect(getGlobalHookRunnerMock).not.toHaveBeenCalled();
  });

  it("fails closed when a persisted scanner record is dropped after its manifest breaks", async () => {
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "scanner manifest could not be parsed",
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
          startup: { activationCapabilities: ["hook"] },
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
      trigger: { kind: "capability", capability: "hook" },
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

    expect(result).toEqual({
      blocked: {
        code: "security_scan_failed",
        reason:
          "Installation blocked because before_install hook failed: hook provider manifest discovery failed: scanner manifest could not be parsed",
      },
    });
  });

  it("recovers a malformed scanner by manifest path when its discovery id hint differs", async () => {
    const manifestPath = "/plugins/scanner/openclaw.plugin.json";
    loadPluginRegistrySnapshotMock.mockReturnValue({
      diagnostics: [
        {
          level: "error",
          message: "scanner manifest could not be parsed",
          pluginId: "package-id-hint",
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
          pluginId: "canonical-scanner",
          startup: { activationCapabilities: ["hook"] },
        },
      ],
    });
    resolveManifestActivationPlanMock.mockReturnValue({
      diagnostics: [],
      entries: [],
      pluginIds: [],
      trigger: { kind: "capability", capability: "hook" },
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

    expect(result?.blocked?.reason).toContain("scanner manifest could not be parsed");
    expect(resolveManifestActivationPlanMock).toHaveBeenCalledWith(
      expect.objectContaining({
        onlyPluginIds: ["canonical-scanner"],
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
          startup: { activationCapabilities: ["hook"] },
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
      trigger: { kind: "capability", capability: "hook" },
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
          startup: { activationCapabilities: ["hook"] },
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
      trigger: { kind: "capability", capability: "hook" },
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
          startup: { activationCapabilities: ["hook"] },
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
          reasons: ["activation-capability-hint"],
        },
      ],
      pluginIds: ["scanner"],
      trigger: { kind: "capability", capability: "hook" },
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
          reasons: ["activation-capability-hint"],
        },
        {
          pluginId: "Scanner-X",
          origin: "global",
          reasons: ["activation-capability-hint"],
        },
      ],
      pluginIds: ["Local-Scanner", "Scanner-X"],
      trigger: { kind: "capability", capability: "hook" },
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
      workspaceDir: expect.any(String),
      onlyPluginIds: ["Local-Scanner", "Scanner-X"],
    });
  });

  it("preserves policy and hook metadata for published lazy install chunks", async () => {
    const warnings: string[] = [];
    const hasHooks = vi.fn().mockReturnValue(true);
    const runBeforeInstall = vi.fn().mockResolvedValue(undefined);
    getGlobalHookRunnerMock.mockReturnValue({ hasHooks, runBeforeInstall });
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
