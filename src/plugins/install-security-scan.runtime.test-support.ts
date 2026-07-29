import { vi } from "vitest";

export const runInstallPolicyMock = vi.fn();
export const findBlockedManifestDependenciesMock = vi.fn();
export const findBlockedNodeModulesDirectoryMock = vi.fn();
export const findBlockedNodeModulesFileAliasMock = vi.fn();
export const findBlockedPackageDirectoryInPathMock = vi.fn();
export const findBlockedPackageFileAliasInPathMock = vi.fn();
export const getGlobalHookRunnerMock = vi.fn();
const getIsolatedGlobalHookRunnerRegistryMock = vi.fn();
const collectLivePluginRegistriesMock = vi.fn();
const getPluginRegistryWorkspaceDirMock = vi.fn();
const createHookRunnerMock = vi.fn();
export const resolveManifestActivationPlanMock = vi.fn();
export const loadPluginRegistrySnapshotMock = vi.fn();
export const loadIsolatedPluginRegistryMock = vi.fn();
const loadInstalledPluginIndexInstallRecordsSyncMock = vi.fn();
export const readPersistedInstalledPluginIndexSyncMock = vi.fn();
export const getRuntimeConfigMock = vi.fn();

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

export function resetInstallSecurityScanRuntimeMocks() {
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
}

export function useIsolatedSdkBeforeInstallHook(pluginId = "sdk-install-gate") {
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
