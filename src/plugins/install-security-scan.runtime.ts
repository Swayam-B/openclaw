// Runtime bridge for plugin install security scanning.
import fs from "node:fs/promises";
import path from "node:path";
import { resolveAgentWorkspaceDir, resolveDefaultAgentId } from "../agents/agent-scope-config.js";
import { getRuntimeConfig } from "../config/config.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { formatErrorMessage } from "../infra/errors.js";
import { resolveUserPath } from "../infra/home-dir.js";
import { tryReadJson } from "../infra/json-files.js";
import { resolveOpenClawPackageRootSync } from "../infra/openclaw-root.js";
import { parseStrictPositiveInteger } from "../infra/parse-finite-number.js";
import {
  runInstallPolicy,
  type InstallPolicyFinding,
  type InstallPolicyOrigin,
  type InstallPolicyRequestKind,
  type InstallPolicySource,
} from "../security/install-policy.js";
import { isPathInside } from "../security/scan-paths.js";
import { resolveManifestActivationPlan } from "./activation-planner.js";
import { normalizePluginsConfig } from "./config-state.js";
import {
  findBlockedManifestDependencies,
  findBlockedNodeModulesDirectory,
  findBlockedNodeModulesFileAlias,
  findBlockedPackageDirectoryInPath,
  findBlockedPackageFileAliasInPath,
  type BlockedPackageDirectoryFinding,
  type BlockedPackageFileFinding,
} from "./dependency-denylist.js";
import { resolveExplicitEffectivePluginIds } from "./effective-plugin-ids.js";
import type { GlobalHookRunnerRegistry } from "./hook-registry.types.js";
import { getIsolatedGlobalHookRunnerRegistry } from "./hook-runner-global-state.js";
import { createHookRunner, type HookRunner } from "./hooks.js";
import { createBeforeInstallHookPayload } from "./install-policy-context.js";
import type { InstallSafetyOverrides } from "./install-security-scan.types.js";
import { loadInstalledPluginIndexInstallRecordsSync } from "./installed-plugin-index-record-reader.js";
import { readPersistedInstalledPluginIndexSync } from "./installed-plugin-index-store.js";
import type { InstalledPluginIndex } from "./installed-plugin-index.js";
import { normalizePluginPolicyId } from "./plugin-policy-id.js";
import { pluginRegistryConfigMatches } from "./plugin-registry-config-provenance.js";
import { loadPluginRegistrySnapshot } from "./plugin-registry-snapshot.js";
import type { PluginRegistry } from "./registry-types.js";
import { collectLivePluginRegistries, getPluginRegistryWorkspaceDir } from "./runtime.js";
import { loadIsolatedPluginRegistry } from "./runtime/runtime-registry-loader.js";

type InstallScanLogger = {
  warn?: (message: string) => void;
};

function resolveBeforeInstallHookRunner(params: {
  allowedPluginIds: ReadonlySet<string> | null;
  config: OpenClawConfig;
  disableAllPlugins: boolean;
  disabledPluginIds: ReadonlySet<string>;
  eligibleLiveProviderIds: readonly string[];
  hookProviderIds: readonly string[];
  index: InstalledPluginIndex;
  logger: InstallScanLogger;
  workspaceDir: string;
}): HookRunner | null {
  const passesCurrentPolicy = (pluginId: string) => {
    const normalizedId = normalizePluginPolicyId(pluginId);
    return (
      !params.disableAllPlugins &&
      (params.allowedPluginIds === null || params.allowedPluginIds.has(normalizedId)) &&
      !params.disabledPluginIds.has(normalizedId)
    );
  };
  const currentLiveProviderIds = new Set(
    [...params.hookProviderIds, ...params.eligibleLiveProviderIds].map((pluginId) =>
      normalizePluginPolicyId(pluginId),
    ),
  );
  const currentProviderById = new Map(
    params.index.plugins
      .filter((plugin) => currentLiveProviderIds.has(normalizePluginPolicyId(plugin.pluginId)))
      .map((plugin) => [normalizePluginPolicyId(plugin.pluginId), plugin]),
  );
  const livePluginMatchesCurrentProvider = (
    registry: PluginRegistry,
    plugin: {
      id: string;
      rootDir?: string;
      source: string;
      status: "loaded" | "disabled" | "error";
    },
  ) => {
    if (plugin.status !== "loaded") {
      return false;
    }
    const currentProvider = currentProviderById.get(normalizePluginPolicyId(plugin.id));
    if (!currentProvider) {
      return false;
    }
    if (
      !pluginRegistryConfigMatches({
        registry,
        config: params.config,
        pluginId: plugin.id,
      })
    ) {
      return false;
    }
    if (currentProvider.source) {
      return path.resolve(plugin.source) === path.resolve(currentProvider.source);
    }
    return (
      plugin.rootDir !== undefined &&
      path.resolve(plugin.rootDir) === path.resolve(currentProvider.rootDir)
    );
  };
  const matchingLiveRegistries = collectLivePluginRegistries()
    .filter((registry) => {
      const registryWorkspaceDir = getPluginRegistryWorkspaceDir(registry);
      return (
        registryWorkspaceDir !== undefined &&
        path.resolve(registryWorkspaceDir) === path.resolve(params.workspaceDir)
      );
    })
    .map((registry): GlobalHookRunnerRegistry => {
      const reusablePluginIds = new Set(
        registry.plugins
          .filter((plugin) => livePluginMatchesCurrentProvider(registry, plugin))
          .map((plugin) => normalizePluginPolicyId(plugin.id)),
      );
      return {
        hooks: registry.hooks.filter((hook) =>
          reusablePluginIds.has(normalizePluginPolicyId(hook.pluginId)),
        ),
        typedHooks: registry.typedHooks.filter((hook) =>
          reusablePluginIds.has(normalizePluginPolicyId(hook.pluginId)),
        ),
        plugins: registry.plugins.filter((plugin) =>
          reusablePluginIds.has(normalizePluginPolicyId(plugin.id)),
        ),
      };
    });
  const isolatedGlobalRegistry = getIsolatedGlobalHookRunnerRegistry();
  const registrySources: GlobalHookRunnerRegistry[] = [
    ...(isolatedGlobalRegistry ? [isolatedGlobalRegistry] : []),
    ...matchingLiveRegistries,
  ];
  const hookOwnerByPluginId = new Map<string, GlobalHookRunnerRegistry>();
  for (const registry of registrySources) {
    const providerIds = new Set(
      registry.typedHooks
        .filter((hook) => hook.hookName === "before_install")
        .map((hook) => normalizePluginPolicyId(hook.pluginId)),
    );
    for (const plugin of registry.plugins) {
      const pluginId = normalizePluginPolicyId(plugin.id);
      if (
        plugin.status === "loaded" &&
        providerIds.has(pluginId) &&
        !hookOwnerByPluginId.has(pluginId)
      ) {
        hookOwnerByPluginId.set(pluginId, registry);
      }
    }
    for (const pluginId of providerIds) {
      if (
        !hookOwnerByPluginId.has(pluginId) &&
        !registry.plugins.some((plugin) => normalizePluginPolicyId(plugin.id) === pluginId)
      ) {
        hookOwnerByPluginId.set(pluginId, registry);
      }
    }
  }
  const globalRegistry: GlobalHookRunnerRegistry | null =
    registrySources.length > 0
      ? {
          hooks: registrySources.flatMap((registry) =>
            registry.hooks.filter(
              (hook) =>
                hookOwnerByPluginId.get(normalizePluginPolicyId(hook.pluginId)) === registry,
            ),
          ),
          typedHooks: registrySources.flatMap((registry) =>
            registry.typedHooks.filter(
              (hook) =>
                hookOwnerByPluginId.get(normalizePluginPolicyId(hook.pluginId)) === registry,
            ),
          ),
          plugins: registrySources.flatMap((registry) =>
            registry.plugins.filter(
              (plugin) => hookOwnerByPluginId.get(normalizePluginPolicyId(plugin.id)) === registry,
            ),
          ),
        }
      : null;
  const loadedGlobalPluginIds = new Set(
    globalRegistry?.plugins
      .filter((plugin) => plugin.status === "loaded")
      .map((plugin) => normalizePluginPolicyId(plugin.id)) ?? [],
  );
  const globalBeforeInstallProviderIds = new Set(
    globalRegistry?.typedHooks
      .filter((hook) => hook.hookName === "before_install")
      .map((hook) => normalizePluginPolicyId(hook.pluginId)) ?? [],
  );
  const hookProviderIdsToLoad = params.hookProviderIds.filter((pluginId) => {
    const normalizedId = normalizePluginPolicyId(pluginId);
    return (
      passesCurrentPolicy(normalizedId) &&
      !(loadedGlobalPluginIds.has(normalizedId) && globalBeforeInstallProviderIds.has(normalizedId))
    );
  });
  const isolatedRegistry =
    hookProviderIdsToLoad.length > 0
      ? loadIsolatedPluginRegistry({
          config: params.config,
          index: params.index,
          workspaceDir: params.workspaceDir,
          onlyPluginIds: hookProviderIdsToLoad,
        })
      : undefined;
  const isolatedBeforeInstallProviderIds = new Set(
    isolatedRegistry?.typedHooks
      .filter((hook) => hook.hookName === "before_install")
      .map((hook) => normalizePluginPolicyId(hook.pluginId)) ?? [],
  );
  const missingIsolatedProviders = hookProviderIdsToLoad.filter(
    (pluginId) => !isolatedBeforeInstallProviderIds.has(normalizePluginPolicyId(pluginId)),
  );
  if (missingIsolatedProviders.length > 0) {
    throw new Error(
      `hook providers did not register before_install in install-scan mode: ${missingIsolatedProviders.join(", ")}`,
    );
  }
  if (!isolatedRegistry && !globalRegistry) {
    return null;
  }
  const isolatedPluginIds = new Set(
    isolatedRegistry?.plugins.map((plugin) => normalizePluginPolicyId(plugin.id)) ?? [],
  );
  const includeGlobalPlugin = (pluginId: string) => {
    const normalizedId = normalizePluginPolicyId(pluginId);
    if (
      isolatedGlobalRegistry &&
      hookOwnerByPluginId.get(normalizedId) === isolatedGlobalRegistry
    ) {
      return true;
    }
    return passesCurrentPolicy(normalizedId) && !isolatedPluginIds.has(normalizedId);
  };
  const registry: GlobalHookRunnerRegistry = {
    hooks: [
      ...(isolatedRegistry?.hooks ?? []),
      ...(globalRegistry?.hooks.filter((hook) => includeGlobalPlugin(hook.pluginId)) ?? []),
    ],
    typedHooks: [
      ...(isolatedRegistry?.typedHooks ?? []),
      ...(globalRegistry?.typedHooks.filter((hook) => includeGlobalPlugin(hook.pluginId)) ?? []),
    ],
    plugins: [
      ...(isolatedRegistry?.plugins ?? []),
      ...(globalRegistry?.plugins.filter((plugin) => includeGlobalPlugin(plugin.id)) ?? []),
    ],
  };
  const warn = params.logger.warn ?? (() => {});
  return createHookRunner(registry, {
    logger: {
      debug: () => {},
      warn,
      error: warn,
    },
    catchErrors: true,
    failurePolicyByHook: {
      before_install: "fail-closed",
    },
  });
}

const FULL_GIT_COMMIT_PATTERN = /^[0-9a-f]{40}$/i;

type PluginInstallRequestKind = Exclude<InstallPolicyRequestKind, "skill-install">;

function formatInstallPolicyWarning(finding: InstallPolicyFinding): string {
  const location = finding.file
    ? ` (${finding.file}${finding.line ? `:${finding.line}` : ""})`
    : "";
  return `Install policy: ${finding.message}${location}`;
}

type InstallScanFinding = {
  ruleId: string;
  severity: "info" | "warn" | "critical";
  file: string;
  line: number;
  message: string;
  evidence?: string;
};

type BuiltinInstallScan = {
  status: "ok" | "error";
  scannedFiles: number;
  critical: number;
  warn: number;
  info: number;
  findings: InstallScanFinding[];
  error?: string;
};

type PackageExecutableScanMetadata = {
  runtimeExtensions?: readonly string[];
  runtimeSetupEntry?: string;
  setupEntry?: string;
};

type PackageManifest = {
  name?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  overrides?: unknown;
  peerDependencies?: Record<string, string>;
};

type PackageManifestTraversalLimits = {
  maxDepth: number;
  maxDirectories: number;
  maxManifests: number;
};

type PackageManifestTraversalResult = {
  blockedDirectoryFinding?: BlockedPackageDirectoryFinding;
  blockedFileFinding?: BlockedPackageFileFinding;
  packageManifestPaths: string[];
};

type InstalledPackageScanRoot = {
  packageDir: string;
  realPath: string;
};

type SkillInstallSpec = {
  id?: string;
  kind: "brew" | "node" | "go" | "uv" | "download";
  label?: string;
  bins?: string[];
  os?: string[];
  formula?: string;
  package?: string;
  module?: string;
  url?: string;
  archive?: string;
  extract?: boolean;
  stripComponents?: number;
  targetDir?: string;
};

export type InstallSecurityScanResult = {
  blocked?: {
    code?: "security_scan_blocked" | "security_scan_failed";
    reason: string;
  };
};

const DEFAULT_PACKAGE_MANIFEST_TRAVERSAL_LIMITS: PackageManifestTraversalLimits = {
  maxDepth: 64,
  maxDirectories: 10_000,
  maxManifests: 10_000,
};

function buildBlockedDependencyManifestLabel(params: {
  manifestPackageName?: string;
  manifestRelativePath: string;
}) {
  const manifestLabel =
    typeof params.manifestPackageName === "string" && params.manifestPackageName.trim()
      ? `${params.manifestPackageName.trim()} (${params.manifestRelativePath})`
      : params.manifestRelativePath;
  return manifestLabel;
}

function buildBlockedDependencyReason(params: {
  findings: Array<{
    dependencyName: string;
    declaredAs?: string;
    field: "dependencies" | "name" | "optionalDependencies" | "overrides" | "peerDependencies";
  }>;
  manifestPackageName?: string;
  manifestRelativePath: string;
  targetLabel: string;
}) {
  const manifestLabel = buildBlockedDependencyManifestLabel({
    manifestPackageName: params.manifestPackageName,
    manifestRelativePath: params.manifestRelativePath,
  });
  const findingSummary = params.findings
    .map((finding) =>
      finding.field === "name"
        ? `"${finding.dependencyName}" as package name`
        : finding.declaredAs
          ? `"${finding.dependencyName}" via alias "${finding.declaredAs}" in ${finding.field}`
          : `"${finding.dependencyName}" in ${finding.field}`,
    )
    .join(", ");
  return `${params.targetLabel} blocked: blocked dependencies ${findingSummary} declared in ${manifestLabel}.`;
}

function buildBlockedDependencyDirectoryReason(params: {
  dependencyName: string;
  directoryRelativePath: string;
  targetLabel: string;
}) {
  return `${params.targetLabel} blocked: blocked dependency directory "${params.dependencyName}" declared at ${params.directoryRelativePath}.`;
}

function buildBlockedDependencyFileReason(params: {
  dependencyName: string;
  fileRelativePath: string;
  targetLabel: string;
}) {
  return `${params.targetLabel} blocked: blocked dependency file alias "${params.dependencyName}" declared at ${params.fileRelativePath}.`;
}

function pathContainsNodeModulesSegment(relativePath: string): boolean {
  return relativePath
    .split(/[\\/]+/)
    .map((segment) => segment.trim().toLowerCase())
    .includes("node_modules");
}

function isPackageRootOpenClawPeerSymlink(segments: string[]): boolean {
  return (
    (segments.length === 2 && segments[0] === "node_modules" && segments[1] === "openclaw") ||
    (segments.length === 3 &&
      segments[0] === "node_modules" &&
      segments[1] === ".bin" &&
      segments[2] === "openclaw")
  );
}

function isManagedNpmRootPackagePeerSymlink(segments: string[]): boolean {
  if (segments[0] !== "node_modules") {
    return false;
  }
  const packageEndIndex = segments[1]?.startsWith("@") ? 3 : 2;
  const packageNameSegments = segments.slice(1, packageEndIndex);
  if (
    packageNameSegments.length === 0 ||
    packageNameSegments.some((segment) => !segment || segment === "." || segment === "..")
  ) {
    return false;
  }
  return isPackageRootOpenClawPeerSymlink(segments.slice(packageEndIndex));
}

function isTrustedOpenClawPeerSymlink(params: {
  allowManagedNpmRootPackagePeerSymlinks?: boolean;
  relativePath: string;
}): boolean {
  const segments = params.relativePath.split(/[\\/]+/);
  return (
    isPackageRootOpenClawPeerSymlink(segments) ||
    (params.allowManagedNpmRootPackagePeerSymlinks === true &&
      isManagedNpmRootPackagePeerSymlink(segments))
  );
}

async function resolveTrustedHostOpenClawRootRealPath(): Promise<string | null> {
  const hostRoot = resolveOpenClawPackageRootSync({
    argv1: process.argv[1],
    cwd: process.cwd(),
    moduleUrl: import.meta.url,
  });
  if (!hostRoot) {
    return null;
  }
  return await fs.realpath(hostRoot).catch(() => path.resolve(hostRoot));
}

function isTrustedHostOpenClawPath(params: {
  resolvedTargetPath: string;
  trustedHostOpenClawRootRealPath: string | null;
}): boolean {
  return (
    params.trustedHostOpenClawRootRealPath !== null &&
    isPathInside(params.trustedHostOpenClawRootRealPath, params.resolvedTargetPath)
  );
}

async function inspectNodeModulesSymlinkTarget(params: {
  allowManagedNpmRootPackagePeerSymlinks?: boolean;
  rootRealPath: string;
  symlinkPath: string;
  symlinkRelativePath: string;
  trustedHostOpenClawRootRealPath: string | null;
}): Promise<
  Pick<PackageManifestTraversalResult, "blockedDirectoryFinding" | "blockedFileFinding">
> {
  let resolvedTargetPath: string;
  try {
    resolvedTargetPath = await fs.realpath(params.symlinkPath);
  } catch (error) {
    throw new Error(
      `manifest dependency scan could not resolve symlink target ${params.symlinkRelativePath}: ${String(error)}`,
      {
        cause: error,
      },
    );
  }

  if (!isPathInside(params.rootRealPath, resolvedTargetPath)) {
    if (
      isTrustedOpenClawPeerSymlink({
        allowManagedNpmRootPackagePeerSymlinks: params.allowManagedNpmRootPackagePeerSymlinks,
        relativePath: params.symlinkRelativePath,
      }) &&
      isTrustedHostOpenClawPath({
        resolvedTargetPath,
        trustedHostOpenClawRootRealPath: params.trustedHostOpenClawRootRealPath,
      })
    ) {
      return {};
    }
    throw new Error(
      `manifest dependency scan found node_modules symlink target outside install root at ${params.symlinkRelativePath}`,
    );
  }

  const resolvedTargetStats = await fs.stat(resolvedTargetPath);
  const resolvedTargetRelativePath = path.relative(params.rootRealPath, resolvedTargetPath);
  const blockedDirectoryFinding = findBlockedPackageDirectoryInPath({
    pathRelativeToRoot: resolvedTargetRelativePath,
  });
  return {
    blockedDirectoryFinding,
    blockedFileFinding: resolvedTargetStats.isFile()
      ? findBlockedPackageFileAliasInPath({
          pathRelativeToRoot: resolvedTargetRelativePath,
        })
      : undefined,
  };
}

function readPositiveIntegerEnv(name: string, fallback: number): number {
  const rawValue = process.env[name];
  if (!rawValue) {
    return fallback;
  }
  const parsedValue = parseStrictPositiveInteger(rawValue);
  return parsedValue ?? fallback;
}

function resolvePackageManifestTraversalLimits(): PackageManifestTraversalLimits {
  return {
    maxDepth: readPositiveIntegerEnv(
      "OPENCLAW_INSTALL_SCAN_MAX_DEPTH",
      DEFAULT_PACKAGE_MANIFEST_TRAVERSAL_LIMITS.maxDepth,
    ),
    maxDirectories: readPositiveIntegerEnv(
      "OPENCLAW_INSTALL_SCAN_MAX_DIRECTORIES",
      DEFAULT_PACKAGE_MANIFEST_TRAVERSAL_LIMITS.maxDirectories,
    ),
    maxManifests: readPositiveIntegerEnv(
      "OPENCLAW_INSTALL_SCAN_MAX_MANIFESTS",
      DEFAULT_PACKAGE_MANIFEST_TRAVERSAL_LIMITS.maxManifests,
    ),
  };
}

function isSamePathOrInside(parentPath: string, candidatePath: string): boolean {
  return parentPath === candidatePath || isPathInside(parentPath, candidatePath);
}

function getErrnoCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

function isInstallScannableDependencyName(name: string): boolean {
  if (name.startsWith("@")) {
    const parts = name.split("/");
    return (
      parts.length === 2 && parts.every((part) => part.length > 0 && part !== "." && part !== "..")
    );
  }
  return (
    name.length > 0 && !name.includes("/") && !name.includes("\\") && name !== "." && name !== ".."
  );
}

function collectManifestRuntimeDependencyNames(manifest: PackageManifest): string[] {
  const dependencyNames = new Set<string>();
  for (const dependencies of [manifest.dependencies, manifest.optionalDependencies]) {
    for (const dependencyName of Object.keys(dependencies ?? {})) {
      if (isInstallScannableDependencyName(dependencyName)) {
        dependencyNames.add(dependencyName);
      }
    }
  }
  for (const dependencyName of Object.keys(manifest.peerDependencies ?? {})) {
    if (dependencyName !== "openclaw" && isInstallScannableDependencyName(dependencyName)) {
      dependencyNames.add(dependencyName);
    }
  }
  return [...dependencyNames].toSorted((left, right) => left.localeCompare(right));
}

async function resolveInstalledPackageScanRoot(params: {
  boundaryRealPath: string;
  dependencyName: string;
  packageDir: string;
}): Promise<InstalledPackageScanRoot | undefined> {
  const packageDir = path.join(params.packageDir, "node_modules", params.dependencyName);
  let stats: Awaited<ReturnType<typeof fs.stat>>;
  try {
    stats = await fs.stat(packageDir);
  } catch (error) {
    if (getErrnoCode(error) === "ENOENT") {
      return undefined;
    }
    throw error;
  }
  if (!stats.isDirectory()) {
    return undefined;
  }

  const realPath = await fs.realpath(packageDir).catch(() => path.resolve(packageDir));
  if (!isSamePathOrInside(params.boundaryRealPath, realPath)) {
    throw new Error(
      `installed dependency scan found package outside install root at ${packageDir}`,
    );
  }
  return { packageDir, realPath };
}

async function collectInstalledPackageScanRoots(params: {
  additionalPackageDirs?: string[];
  dependencyScanRootDir?: string;
  packageDir: string;
}): Promise<string[]> {
  const limits = resolvePackageManifestTraversalLimits();
  const boundaryDir = params.dependencyScanRootDir ?? params.packageDir;
  const boundaryRealPath = await fs.realpath(boundaryDir).catch(() => path.resolve(boundaryDir));
  const packageRealPath = await fs
    .realpath(params.packageDir)
    .catch(() => path.resolve(params.packageDir));
  if (!isSamePathOrInside(boundaryRealPath, packageRealPath)) {
    throw new Error(
      `installed dependency scan found package outside install root at ${params.packageDir}`,
    );
  }

  const queue: InstalledPackageScanRoot[] = [
    { packageDir: params.packageDir, realPath: packageRealPath },
  ];
  for (const packageDir of params.additionalPackageDirs ?? []) {
    const realPath = await fs.realpath(packageDir).catch(() => path.resolve(packageDir));
    if (!isSamePathOrInside(boundaryRealPath, realPath)) {
      throw new Error(
        `installed dependency scan found package outside install root at ${packageDir}`,
      );
    }
    queue.push({ packageDir, realPath });
  }
  const visitedRealPaths = new Set<string>();
  const scanRoots: string[] = [];
  let queueIndex = 0;

  while (queueIndex < queue.length) {
    const current = queue[queueIndex];
    queueIndex += 1;
    if (!current || visitedRealPaths.has(current.realPath)) {
      continue;
    }
    visitedRealPaths.add(current.realPath);
    if (visitedRealPaths.size > limits.maxDirectories) {
      throw new Error(
        `installed dependency scan exceeded max packages (${limits.maxDirectories}) under ${boundaryDir}`,
      );
    }
    scanRoots.push(current.packageDir);

    const manifest = await tryReadJson<PackageManifest>(
      path.join(current.packageDir, "package.json"),
    );
    if (!manifest) {
      continue;
    }
    for (const dependencyName of collectManifestRuntimeDependencyNames(manifest)) {
      const nestedCandidate = await resolveInstalledPackageScanRoot({
        boundaryRealPath,
        dependencyName,
        packageDir: current.packageDir,
      });
      const candidate =
        nestedCandidate ??
        (params.dependencyScanRootDir
          ? await resolveInstalledPackageScanRoot({
              boundaryRealPath,
              dependencyName,
              packageDir: params.dependencyScanRootDir,
            })
          : undefined);
      if (candidate && !visitedRealPaths.has(candidate.realPath)) {
        queue.push(candidate);
      }
    }
  }

  return scanRoots;
}

async function collectNonOverlappingPackageScanRoots(packageDirs: string[]): Promise<string[]> {
  const selectedRoots: InstalledPackageScanRoot[] = [];
  for (const packageDir of packageDirs) {
    const realPath = await fs.realpath(packageDir).catch(() => path.resolve(packageDir));
    if (selectedRoots.some((selectedRoot) => isSamePathOrInside(selectedRoot.realPath, realPath))) {
      continue;
    }
    selectedRoots.push({ packageDir, realPath });
  }
  return selectedRoots.map((selectedRoot) => selectedRoot.packageDir);
}

async function collectPackageManifestPaths(params: {
  allowManagedNpmRootPackagePeerSymlinks?: boolean;
  rootDir: string;
}): Promise<PackageManifestTraversalResult> {
  const limits = resolvePackageManifestTraversalLimits();
  const rootDir = params.rootDir;
  const rootRealPath = await fs.realpath(rootDir).catch(() => rootDir);
  const trustedHostOpenClawRootRealPath = await resolveTrustedHostOpenClawRootRealPath();
  const queue: Array<{ depth: number; dir: string }> = [{ depth: 0, dir: rootDir }];
  const packageManifestPaths: string[] = [];
  const visitedDirectories = new Set<string>();
  let firstBlockedDirectoryFinding: BlockedPackageDirectoryFinding | undefined;
  let firstBlockedFileFinding: BlockedPackageFileFinding | undefined;
  let queueIndex = 0;

  while (queueIndex < queue.length) {
    const current = queue[queueIndex];
    queueIndex += 1;
    if (!current) {
      continue;
    }

    if (current.depth > limits.maxDepth) {
      throw new Error(
        `manifest dependency scan exceeded max depth (${limits.maxDepth}) at ${current.dir}`,
      );
    }

    const currentDir = current.dir;
    const currentRealPath = await fs.realpath(currentDir).catch(() => currentDir);
    if (visitedDirectories.has(currentRealPath)) {
      continue;
    }
    visitedDirectories.add(currentRealPath);
    if (visitedDirectories.size > limits.maxDirectories) {
      throw new Error(
        `manifest dependency scan exceeded max directories (${limits.maxDirectories}) under ${rootDir}`,
      );
    }

    let entries: Array<{
      name: string;
      isDirectory(): boolean;
      isFile(): boolean;
      isSymbolicLink(): boolean;
    }>;
    try {
      entries = await fs.readdir(currentDir, { encoding: "utf8", withFileTypes: true });
    } catch (error) {
      throw new Error(`manifest dependency scan could not read ${currentDir}: ${String(error)}`, {
        cause: error,
      });
    }

    for (const entry of entries.toSorted((left, right) => left.name.localeCompare(right.name))) {
      const nextPath = path.join(currentDir, entry.name);
      const relativeNextPath = path.relative(rootDir, nextPath) || entry.name;
      if (entry.isSymbolicLink()) {
        const blockedDirectoryFinding = findBlockedNodeModulesDirectory({
          directoryRelativePath: relativeNextPath,
        });
        if (blockedDirectoryFinding) {
          firstBlockedDirectoryFinding ??= blockedDirectoryFinding;
        }
        const blockedFileFinding = findBlockedNodeModulesFileAlias({
          fileRelativePath: relativeNextPath,
        });
        if (blockedFileFinding) {
          firstBlockedFileFinding ??= blockedFileFinding;
        }
        if (pathContainsNodeModulesSegment(relativeNextPath)) {
          const symlinkTargetInspection = await inspectNodeModulesSymlinkTarget({
            allowManagedNpmRootPackagePeerSymlinks: params.allowManagedNpmRootPackagePeerSymlinks,
            rootRealPath,
            symlinkPath: nextPath,
            symlinkRelativePath: relativeNextPath,
            trustedHostOpenClawRootRealPath,
          });
          if (symlinkTargetInspection.blockedDirectoryFinding) {
            firstBlockedDirectoryFinding ??= symlinkTargetInspection.blockedDirectoryFinding;
          }
          if (symlinkTargetInspection.blockedFileFinding) {
            firstBlockedFileFinding ??= symlinkTargetInspection.blockedFileFinding;
          }
        }
        continue;
      }
      if (entry.isDirectory()) {
        const blockedDirectoryFinding = findBlockedNodeModulesDirectory({
          directoryRelativePath: relativeNextPath,
        });
        if (blockedDirectoryFinding) {
          firstBlockedDirectoryFinding ??= blockedDirectoryFinding;
        }
        queue.push({ depth: current.depth + 1, dir: nextPath });
        continue;
      }
      if (entry.isFile()) {
        const blockedFileFinding = findBlockedNodeModulesFileAlias({
          fileRelativePath: relativeNextPath,
        });
        if (blockedFileFinding) {
          firstBlockedFileFinding ??= blockedFileFinding;
        }
      }
      if (entry.isFile() && entry.name === "package.json") {
        packageManifestPaths.push(nextPath);
        if (packageManifestPaths.length > limits.maxManifests) {
          throw new Error(
            `manifest dependency scan exceeded max manifests (${limits.maxManifests}) under ${rootDir}`,
          );
        }
      }
    }
  }

  return {
    packageManifestPaths,
    blockedDirectoryFinding: firstBlockedDirectoryFinding,
    blockedFileFinding: firstBlockedFileFinding,
  };
}

function formatPackageScanRelativePath(params: {
  packageDir: string;
  relativePath: string;
  relativeRootDir?: string;
}): string {
  if (!params.relativeRootDir) {
    return params.relativePath;
  }
  const packageRelativePath = path.relative(params.relativeRootDir, params.packageDir);
  return packageRelativePath
    ? path.join(packageRelativePath, params.relativePath)
    : params.relativePath;
}

async function scanPluginDependencyDenylist(params: {
  allowManagedNpmRootPackagePeerSymlinks?: boolean;
  logger: InstallScanLogger;
  packageDir: string;
  relativeRootDir?: string;
  targetLabel: string;
}): Promise<InstallSecurityScanResult | undefined> {
  const traversalResult = await collectPackageManifestPaths({
    allowManagedNpmRootPackagePeerSymlinks: params.allowManagedNpmRootPackagePeerSymlinks,
    rootDir: params.packageDir,
  });
  for (const manifestPath of traversalResult.packageManifestPaths) {
    const manifest = await tryReadJson<PackageManifest>(manifestPath);
    if (!manifest) {
      continue;
    }

    const blockedDependencies = findBlockedManifestDependencies(manifest);
    if (blockedDependencies.length === 0) {
      continue;
    }

    const manifestRelativePath = formatPackageScanRelativePath({
      packageDir: params.packageDir,
      relativePath: path.relative(params.packageDir, manifestPath) || "package.json",
      relativeRootDir: params.relativeRootDir,
    });
    const reason = buildBlockedDependencyReason({
      findings: blockedDependencies,
      manifestPackageName: manifest.name,
      manifestRelativePath,
      targetLabel: params.targetLabel,
    });
    params.logger.warn?.(`WARNING: ${reason}`);
    return {
      blocked: {
        code: "security_scan_blocked",
        reason,
      },
    };
  }

  if (traversalResult.blockedDirectoryFinding) {
    const reason = buildBlockedDependencyDirectoryReason({
      dependencyName: traversalResult.blockedDirectoryFinding.dependencyName,
      directoryRelativePath: formatPackageScanRelativePath({
        packageDir: params.packageDir,
        relativePath: traversalResult.blockedDirectoryFinding.directoryRelativePath,
        relativeRootDir: params.relativeRootDir,
      }),
      targetLabel: params.targetLabel,
    });
    params.logger.warn?.(`WARNING: ${reason}`);
    return {
      blocked: {
        code: "security_scan_blocked",
        reason,
      },
    };
  }
  if (traversalResult.blockedFileFinding) {
    const reason = buildBlockedDependencyFileReason({
      dependencyName: traversalResult.blockedFileFinding.dependencyName,
      fileRelativePath: formatPackageScanRelativePath({
        packageDir: params.packageDir,
        relativePath: traversalResult.blockedFileFinding.fileRelativePath,
        relativeRootDir: params.relativeRootDir,
      }),
      targetLabel: params.targetLabel,
    });
    params.logger.warn?.(`WARNING: ${reason}`);
    return {
      blocked: {
        code: "security_scan_blocked",
        reason,
      },
    };
  }

  return undefined;
}

async function runBeforeInstallHook(params: {
  config?: OpenClawConfig;
  workspaceDir?: string;
  logger: InstallScanLogger;
  installLabel: string;
  origin: string;
  sourcePath: string;
  sourcePathKind: "file" | "directory";
  source?: InstallPolicySource;
  targetName: string;
  targetType: "skill" | "plugin";
  requestKind: InstallPolicyRequestKind;
  requestMode: "install" | "update";
  requestedSpecifier?: string;
  builtinScan?: BuiltinInstallScan;
  skill?: {
    installId: string;
    installSpec?: SkillInstallSpec;
  };
  plugin?: {
    contentType: "bundle" | "package" | "file";
    pluginId: string;
    packageName?: string;
    manifestId?: string;
    version?: string;
    extensions?: string[];
  };
}): Promise<InstallSecurityScanResult | undefined> {
  try {
    const config = params.config ?? getRuntimeConfig();
    const normalizedPlugins = normalizePluginsConfig(config.plugins);
    const workspaceDir =
      params.workspaceDir ?? resolveAgentWorkspaceDir(config, resolveDefaultAgentId(config));
    const currentLoadPathSelections = await Promise.all(
      normalizedPlugins.loadPaths.map(async (loadPath) => {
        const resolvedPath = path.resolve(resolveUserPath(loadPath, process.env));
        const comparablePaths = new Set([resolvedPath]);
        try {
          const stat = await fs.stat(resolvedPath);
          comparablePaths.add(await fs.realpath(resolvedPath));
          return {
            allowsDescendants: stat.isDirectory(),
            paths: [...comparablePaths],
          };
        } catch {
          try {
            const linkTarget = await fs.readlink(resolvedPath);
            comparablePaths.add(path.resolve(path.dirname(resolvedPath), linkTarget));
          } catch {
            // Missing configured directories have no extra path identity to recover.
          }
          return {
            allowsDescendants: true,
            paths: [...comparablePaths],
          };
        }
      }),
    );
    const recordComparablePaths = (plugin: {
      manifestPath?: string;
      rootDir?: string;
      source?: string;
      setupSource?: string;
      packageJson?: {
        path: string;
      };
    }) => {
      const packageJsonPath =
        plugin.packageJson?.path && plugin.rootDir
          ? path.resolve(plugin.rootDir, plugin.packageJson.path)
          : undefined;
      return [
        plugin.manifestPath,
        plugin.rootDir,
        plugin.source,
        plugin.setupSource,
        packageJsonPath,
      ]
        .filter((value): value is string => value !== undefined)
        .map((value) => path.resolve(value));
    };
    const loadPathSelectionContains = (
      selection: (typeof currentLoadPathSelections)[number],
      candidatePath: string,
    ) =>
      selection.paths.some(
        (selectedPath) =>
          selectedPath === candidatePath ||
          (selection.allowsDescendants && isSamePathOrInside(selectedPath, candidatePath)),
      );
    const pluginIndex = loadPluginRegistrySnapshot({
      config,
      installRecords: loadInstalledPluginIndexInstallRecordsSync({ env: process.env }),
      workspaceDir,
      preferPersisted: false,
    });
    const isBlockingProviderDiagnostic = (diagnostic: {
      level: "warn" | "error";
      message: string;
    }) =>
      diagnostic.level === "error" ||
      diagnostic.message.includes("skipping discovery") ||
      diagnostic.message.startsWith("blocked plugin candidate:") ||
      (diagnostic.message.includes("plugin requires ") &&
        diagnostic.message.includes("; skipping load"));
    const currentBlockingDiagnostics = (pluginIndex.diagnostics ?? []).filter(
      isBlockingProviderDiagnostic,
    );
    const persistedPluginIndex =
      currentBlockingDiagnostics.length > 0
        ? readPersistedInstalledPluginIndexSync({ env: process.env })
        : null;
    const diagnosticMatchesRecord = (
      diagnostic: (typeof currentBlockingDiagnostics)[number],
      plugin: {
        pluginId: string;
        manifestPath: string;
        rootDir: string;
        source?: string;
        setupSource?: string;
        packageJson?: {
          path: string;
        };
      },
    ) => {
      if (diagnostic.source !== undefined) {
        const diagnosticSource = path.resolve(diagnostic.source);
        const recordPaths = recordComparablePaths(plugin);
        if (recordPaths.includes(diagnosticSource)) {
          return true;
        }
        const configuredContainer = currentLoadPathSelections.find((selection) =>
          selection.paths.includes(diagnosticSource),
        );
        return (
          configuredContainer !== undefined &&
          recordPaths.some((recordPath) =>
            loadPathSelectionContains(configuredContainer, recordPath),
          )
        );
      }
      return (
        diagnostic.pluginId !== undefined &&
        normalizePluginPolicyId(diagnostic.pluginId) === normalizePluginPolicyId(plugin.pluginId)
      );
    };
    const recordsShareSource = (
      left: {
        manifestPath?: string;
        rootDir?: string;
        source?: string;
        setupSource?: string;
      },
      right: {
        manifestPath?: string;
        rootDir?: string;
        source?: string;
        setupSource?: string;
      },
    ) => {
      const leftPaths = [left.manifestPath, left.rootDir, left.source, left.setupSource]
        .filter((value): value is string => value !== undefined)
        .map((value) => path.resolve(value));
      const rightPaths = new Set(
        [right.manifestPath, right.rootDir, right.source, right.setupSource]
          .filter((value): value is string => value !== undefined)
          .map((value) => path.resolve(value)),
      );
      return leftPaths.some((value) => rightPaths.has(value));
    };
    const persistedDiagnosticOwnerRecords =
      persistedPluginIndex?.plugins.filter((plugin) => {
        const selectedPlugin = pluginIndex.plugins.find(
          (candidate) =>
            normalizePluginPolicyId(candidate.pluginId) ===
            normalizePluginPolicyId(plugin.pluginId),
        );
        if (selectedPlugin && !recordsShareSource(selectedPlugin, plugin)) {
          return false;
        }
        if (
          !currentBlockingDiagnostics.some((diagnostic) =>
            diagnosticMatchesRecord(diagnostic, plugin),
          )
        ) {
          return false;
        }
        return true;
      }) ?? [];
    const pluginRecords = new Map(
      persistedDiagnosticOwnerRecords.map((plugin) => [
        normalizePluginPolicyId(plugin.pluginId),
        plugin,
      ]),
    );
    const currentPluginRecords = new Set(pluginIndex.plugins);
    for (const plugin of pluginIndex.plugins) {
      pluginRecords.set(normalizePluginPolicyId(plugin.pluginId), plugin);
    }
    const isSelectedByCurrentLoadPath = (plugin: {
      manifestPath?: string;
      rootDir?: string;
      source?: string;
      setupSource?: string;
    }) => {
      const recordPaths = recordComparablePaths(plugin);
      return currentLoadPathSelections.some((selection) =>
        recordPaths.some((recordPath) => loadPathSelectionContains(selection, recordPath)),
      );
    };
    const explicitlyEnabledPluginIds = resolveExplicitEffectivePluginIds(config, {
      pluginRecords: [...pluginRecords.values()].map((plugin) =>
        plugin.origin === "config" &&
        !currentPluginRecords.has(plugin) &&
        !isSelectedByCurrentLoadPath(plugin)
          ? { origin: "global", pluginId: plugin.pluginId }
          : plugin,
      ),
    });
    const explicitlyEnabledPluginIdSet = new Set(
      explicitlyEnabledPluginIds.map(normalizePluginPolicyId),
    );
    const recoverableHookProviderRecords = persistedDiagnosticOwnerRecords.filter(
      (plugin) => plugin.startup.activationHooks?.includes("before_install") === true,
    );
    const recoveredHookProviderRecords = recoverableHookProviderRecords.filter((plugin) =>
      explicitlyEnabledPluginIdSet.has(normalizePluginPolicyId(plugin.pluginId)),
    );
    const legacyUnknownHookProviderRecords = persistedDiagnosticOwnerRecords.filter(
      (plugin) =>
        plugin.startup.activationHooks === undefined &&
        explicitlyEnabledPluginIdSet.has(normalizePluginPolicyId(plugin.pluginId)),
    );
    let hookProviderIds: readonly string[] = [];
    if (explicitlyEnabledPluginIds.length > 0) {
      const activationPlan = resolveManifestActivationPlan({
        config,
        workspaceDir,
        onlyPluginIds: explicitlyEnabledPluginIds,
        preferPersisted: false,
        requireExplicitManifestOwnerTrust: true,
        trigger: {
          kind: "hook",
          hook: "before_install",
        },
      });
      const hookProviderIdByNormalizedId = new Map(
        [...pluginIndex.plugins, ...recoveredHookProviderRecords]
          .filter((plugin) => plugin.startup?.activationHooks?.includes("before_install") === true)
          .map((plugin) => [normalizePluginPolicyId(plugin.pluginId), plugin.pluginId]),
      );
      for (const entry of activationPlan.entries) {
        if (entry.reasons.includes("activation-hook-hint")) {
          hookProviderIdByNormalizedId.set(normalizePluginPolicyId(entry.pluginId), entry.pluginId);
        }
      }
      const hookProviderCandidateIds = new Set(hookProviderIdByNormalizedId.keys());
      const activationErrors = [
        ...new Map(
          [
            ...currentBlockingDiagnostics,
            ...activationPlan.diagnostics.filter(isBlockingProviderDiagnostic),
          ]
            .filter((diagnostic) => {
              const diagnosticPluginId = diagnostic.pluginId
                ? normalizePluginPolicyId(diagnostic.pluginId)
                : undefined;
              const selectedPlugin = diagnosticPluginId
                ? pluginIndex.plugins.find(
                    (plugin) => normalizePluginPolicyId(plugin.pluginId) === diagnosticPluginId,
                  )
                : undefined;
              return (
                (diagnosticPluginId !== undefined &&
                  hookProviderCandidateIds.has(diagnosticPluginId) &&
                  (!selectedPlugin || diagnosticMatchesRecord(diagnostic, selectedPlugin))) ||
                recoveredHookProviderRecords.some((plugin) =>
                  diagnosticMatchesRecord(diagnostic, plugin),
                ) ||
                legacyUnknownHookProviderRecords.some((plugin) =>
                  diagnosticMatchesRecord(diagnostic, plugin),
                )
              );
            })
            .map((diagnostic) => [
              `${diagnostic.pluginId ?? ""}\0${diagnostic.source ?? ""}\0${diagnostic.message}`,
              diagnostic,
            ]),
        ).values(),
      ];
      if (activationErrors.length > 0) {
        throw new Error(
          `hook provider manifest discovery failed: ${activationErrors
            .map((diagnostic) => diagnostic.message)
            .join("; ")}`,
        );
      }
      hookProviderIds = [...hookProviderIdByNormalizedId]
        .filter(([pluginId]) => explicitlyEnabledPluginIdSet.has(pluginId))
        .map(([, pluginId]) => pluginId)
        .toSorted((left, right) => left.localeCompare(right));
    }
    const disabledPluginIds = new Set([
      ...normalizedPlugins.deny.map(normalizePluginPolicyId),
      ...Object.entries(normalizedPlugins.entries).flatMap(([pluginId, entry]) =>
        entry?.enabled === false ? [normalizePluginPolicyId(pluginId)] : [],
      ),
      ...pluginIndex.plugins
        .filter((plugin) => !plugin.enabled)
        .map((plugin) => normalizePluginPolicyId(plugin.pluginId)),
    ]);
    const hookRunner = resolveBeforeInstallHookRunner({
      allowedPluginIds:
        normalizedPlugins.allow.length > 0
          ? new Set(normalizedPlugins.allow.map(normalizePluginPolicyId))
          : null,
      config,
      disableAllPlugins: !normalizedPlugins.enabled,
      disabledPluginIds,
      eligibleLiveProviderIds: explicitlyEnabledPluginIds,
      hookProviderIds,
      index: pluginIndex,
      logger: params.logger,
      workspaceDir,
    });
    if (!hookRunner?.hasHooks("before_install")) {
      return undefined;
    }

    const { event, ctx } = createBeforeInstallHookPayload({
      targetName: params.targetName,
      targetType: params.targetType,
      origin: params.origin,
      sourcePath: params.sourcePath,
      sourcePathKind: params.sourcePathKind,
      request: {
        kind: params.requestKind,
        mode: params.requestMode,
        ...(params.requestedSpecifier ? { requestedSpecifier: params.requestedSpecifier } : {}),
      },
      builtinScan: params.builtinScan,
      ...(params.skill ? { skill: params.skill } : {}),
      ...(params.plugin ? { plugin: params.plugin } : {}),
    });
    const hookResult = await hookRunner.runBeforeInstall(event, ctx);
    if (hookResult?.block) {
      const reason = hookResult.blockReason || "Installation blocked by plugin hook";
      params.logger.warn?.(`WARNING: ${params.installLabel} blocked by plugin hook: ${reason}`);
      return { blocked: { code: "security_scan_blocked", reason } };
    }
    if (hookResult?.findings) {
      for (const finding of hookResult.findings) {
        if (finding.severity === "critical" || finding.severity === "warn") {
          params.logger.warn?.(
            `Plugin scanner: ${finding.message} (${finding.file}:${finding.line})`,
          );
        }
      }
    }
  } catch (err) {
    const reason = `Installation blocked because before_install hook failed: ${formatErrorMessage(err)}`;
    params.logger.warn?.(
      `WARNING: ${params.installLabel} blocked by plugin hook failure: ${reason}`,
    );
    return { blocked: { code: "security_scan_failed", reason } };
  }

  return undefined;
}

function formatInstallPolicyOriginForHook(origin: InstallPolicyOrigin): string {
  const type = typeof origin.type === "string" ? origin.type : "unknown";
  if (type === "upload") {
    return "skill-upload";
  }
  const spec = typeof origin.spec === "string" ? origin.spec : undefined;
  const slug = typeof origin.slug === "string" ? origin.slug : undefined;
  return spec ?? slug ?? type;
}

function isMutableGitOrigin(origin: InstallPolicyOrigin | undefined): boolean {
  const ref = typeof origin?.ref === "string" ? origin.ref : undefined;
  return !FULL_GIT_COMMIT_PATTERN.test(ref ?? "");
}

function resolvePolicySource(params: {
  requestKind: InstallPolicyRequestKind;
  origin?: InstallPolicyOrigin;
}): InstallPolicySource {
  if (params.requestKind === "skill-install") {
    switch (params.origin?.type) {
      case "clawhub":
        return { kind: "clawhub", authority: "openclaw", mutable: false, network: true };
      case "git":
        return {
          kind: "git",
          authority: "third-party",
          mutable: isMutableGitOrigin(params.origin),
          network: true,
        };
      case "path":
        return { kind: "local-path", authority: "user", mutable: true, network: false };
      case "upload":
        return { kind: "upload", authority: "user", mutable: false, network: false };
      case "openclaw-bundled":
        return { kind: "bundled", authority: "openclaw", mutable: false, network: false };
      case "openclaw-managed":
      case "openclaw-extra":
        return { kind: "managed", authority: "openclaw", mutable: false, network: false };
      default:
        return { kind: "workspace", authority: "user", mutable: true, network: false };
    }
  }

  switch (params.requestKind) {
    case "plugin-archive":
      return { kind: "archive", authority: "third-party", mutable: true, network: false };
    case "plugin-file":
      return { kind: "file", authority: "user", mutable: true, network: false };
    case "plugin-git":
      return { kind: "git", authority: "third-party", mutable: true, network: true };
    case "plugin-npm":
      return { kind: "npm", authority: "third-party", mutable: false, network: true };
    case "plugin-dir":
      return { kind: "local-path", authority: "user", mutable: true, network: false };
  }
  return { kind: "local-path", authority: "unknown", mutable: true, network: false };
}

function shouldBypassOpenClawInstallFriction(params: {
  source?: InstallPolicySource;
  trustedSourceLinkedOfficialInstall?: boolean;
}): boolean {
  if (params.trustedSourceLinkedOfficialInstall === true) {
    return true;
  }
  const source = params.source;
  if (!source || source.mutable) {
    return false;
  }
  if (source.authority === "official") {
    return source.kind === "clawhub" || source.kind === "git" || source.kind === "npm";
  }
  return (
    source.authority === "openclaw" && (source.kind === "bundled" || source.kind === "managed")
  );
}

async function runOperatorInstallPolicy(params: {
  config?: OpenClawConfig;
  logger: InstallScanLogger;
  origin: InstallPolicyOrigin;
  source?: InstallPolicySource;
  sourcePath: string;
  sourcePathKind: "file" | "directory";
  targetName: string;
  targetType: "skill" | "plugin";
  requestKind: InstallPolicyRequestKind;
  requestMode: "install" | "update";
  requestedSpecifier?: string;
  skill?: {
    installId: string;
    installSpec?: SkillInstallSpec;
  };
  plugin?: {
    contentType: "bundle" | "package" | "file" | "dependency-tree";
    pluginId: string;
    packageName?: string;
    manifestId?: string;
    version?: string;
    extensions?: string[];
  };
  trustedSourceLinkedOfficialInstall?: boolean;
}): Promise<InstallSecurityScanResult | undefined> {
  const result = await runInstallPolicy({
    config: params.config,
    logger: params.logger,
    request: {
      targetName: params.targetName,
      targetType: params.targetType,
      sourcePath: params.sourcePath,
      sourcePathKind: params.sourcePathKind,
      ...(params.source ? { source: params.source } : {}),
      origin: params.origin,
      request: {
        kind: params.requestKind,
        mode: params.requestMode,
        ...(params.requestedSpecifier ? { requestedSpecifier: params.requestedSpecifier } : {}),
      },
      ...(params.skill ? { skill: params.skill } : {}),
      ...(params.plugin ? { plugin: params.plugin } : {}),
    },
  });
  if (!result?.blocked) {
    for (const finding of result?.findings ?? []) {
      if (finding.severity === "critical" || finding.severity === "warn") {
        params.logger.warn?.(formatInstallPolicyWarning(finding));
      }
    }
    return undefined;
  }
  return { blocked: result.blocked };
}

export async function scanBundleInstallSourceRuntime(
  params: InstallSafetyOverrides & {
    config?: OpenClawConfig;
    logger: InstallScanLogger;
    pluginId: string;
    sourceDir: string;
    requestKind?: PluginInstallRequestKind;
    requestedSpecifier?: string;
    mode?: "install" | "update";
    version?: string;
    source?: InstallPolicySource;
  },
): Promise<InstallSecurityScanResult | undefined> {
  const runPolicy = () =>
    runOperatorInstallPolicy({
      config: params.config,
      logger: params.logger,
      origin: { type: "plugin-bundle", ...(params.version ? { version: params.version } : {}) },
      source:
        params.source ?? resolvePolicySource({ requestKind: params.requestKind ?? "plugin-dir" }),
      sourcePath: params.sourceDir,
      sourcePathKind: "directory",
      targetName: params.pluginId,
      targetType: "plugin",
      requestKind: params.requestKind ?? "plugin-dir",
      requestMode: params.mode ?? "install",
      requestedSpecifier: params.requestedSpecifier,
      plugin: {
        contentType: "bundle",
        pluginId: params.pluginId,
        manifestId: params.pluginId,
        ...(params.version ? { version: params.version } : {}),
      },
    });
  if (!shouldBypassOpenClawInstallFriction({ source: params.source })) {
    const dependencyBlocked = await scanPluginDependencyDenylist({
      logger: params.logger,
      packageDir: params.sourceDir,
      targetLabel: `Bundle "${params.pluginId}" installation`,
    });
    if (dependencyBlocked) {
      return dependencyBlocked;
    }
  }

  const policyResult = await runPolicy();
  if (policyResult?.blocked) {
    return policyResult;
  }

  const hookResult = await runBeforeInstallHook({
    config: params.config,
    logger: params.logger,
    installLabel: `Bundle "${params.pluginId}" installation`,
    origin: "plugin-bundle",
    sourcePath: params.sourceDir,
    sourcePathKind: "directory",
    targetName: params.pluginId,
    targetType: "plugin",
    requestKind: params.requestKind ?? "plugin-dir",
    requestMode: params.mode ?? "install",
    requestedSpecifier: params.requestedSpecifier,
    plugin: {
      contentType: "bundle",
      pluginId: params.pluginId,
      manifestId: params.pluginId,
      ...(params.version ? { version: params.version } : {}),
    },
  });
  return hookResult;
}

export async function scanPackageInstallSourceRuntime(
  params: InstallSafetyOverrides & {
    config?: OpenClawConfig;
    extensions: string[];
    logger: InstallScanLogger;
    packageDir: string;
    packageMetadata?: PackageExecutableScanMetadata;
    pluginId: string;
    requestKind?: PluginInstallRequestKind;
    requestedSpecifier?: string;
    mode?: "install" | "update";
    packageName?: string;
    manifestId?: string;
    version?: string;
    source?: InstallPolicySource;
    trustedSourceLinkedOfficialInstall?: boolean;
  },
): Promise<InstallSecurityScanResult | undefined> {
  const runPolicy = () =>
    runOperatorInstallPolicy({
      config: params.config,
      logger: params.logger,
      origin: {
        type: "plugin-package",
        ...(params.packageName ? { packageName: params.packageName } : {}),
        ...(params.version ? { version: params.version } : {}),
      },
      source:
        params.source ?? resolvePolicySource({ requestKind: params.requestKind ?? "plugin-dir" }),
      sourcePath: params.packageDir,
      sourcePathKind: "directory",
      targetName: params.pluginId,
      targetType: "plugin",
      requestKind: params.requestKind ?? "plugin-dir",
      requestMode: params.mode ?? "install",
      requestedSpecifier: params.requestedSpecifier,
      plugin: {
        contentType: "package",
        pluginId: params.pluginId,
        ...(params.packageName ? { packageName: params.packageName } : {}),
        ...(params.manifestId ? { manifestId: params.manifestId } : {}),
        ...(params.version ? { version: params.version } : {}),
        extensions: params.extensions.slice(),
      },
    });
  if (
    !shouldBypassOpenClawInstallFriction({
      source: params.source,
      trustedSourceLinkedOfficialInstall: params.trustedSourceLinkedOfficialInstall,
    })
  ) {
    const dependencyBlocked = await scanPluginDependencyDenylist({
      logger: params.logger,
      packageDir: params.packageDir,
      targetLabel: `Plugin "${params.pluginId}" installation`,
    });
    if (dependencyBlocked) {
      return dependencyBlocked;
    }
  }

  const policyResult = await runPolicy();
  if (policyResult?.blocked) {
    return policyResult;
  }

  const hookResult = await runBeforeInstallHook({
    config: params.config,
    logger: params.logger,
    installLabel: `Plugin "${params.pluginId}" installation`,
    origin: "plugin-package",
    sourcePath: params.packageDir,
    sourcePathKind: "directory",
    targetName: params.pluginId,
    targetType: "plugin",
    requestKind: params.requestKind ?? "plugin-dir",
    requestMode: params.mode ?? "install",
    requestedSpecifier: params.requestedSpecifier,
    plugin: {
      contentType: "package",
      pluginId: params.pluginId,
      ...(params.packageName ? { packageName: params.packageName } : {}),
      ...(params.manifestId ? { manifestId: params.manifestId } : {}),
      ...(params.version ? { version: params.version } : {}),
      extensions: params.extensions.slice(),
    },
  });
  return hookResult;
}

export async function scanInstalledPackageDependencyTreeRuntime(params: {
  additionalPackageDirs?: string[];
  allowManagedNpmRootPackagePeerSymlinks?: boolean;
  config?: OpenClawConfig;
  dangerouslyForceUnsafeInstall?: boolean;
  dependencyScanRootDir?: string;
  logger: InstallScanLogger;
  mode?: "install" | "update";
  packageDir: string;
  pluginId: string;
  requestKind?: PluginInstallRequestKind;
  requestedSpecifier?: string;
  source?: InstallPolicySource;
  trustedSourceLinkedOfficialInstall?: boolean;
}): Promise<InstallSecurityScanResult | undefined> {
  const requestKind = params.requestKind ?? "plugin-npm";
  const runPolicy = () =>
    runOperatorInstallPolicy({
      config: params.config,
      logger: params.logger,
      origin: { type: "plugin-dependency-tree" },
      source: params.source ?? resolvePolicySource({ requestKind }),
      sourcePath: params.dependencyScanRootDir ?? params.packageDir,
      sourcePathKind: "directory",
      targetName: params.pluginId,
      targetType: "plugin",
      requestKind,
      requestMode: params.mode ?? "install",
      requestedSpecifier: params.requestedSpecifier,
      plugin: {
        contentType: "dependency-tree",
        pluginId: params.pluginId,
      },
      trustedSourceLinkedOfficialInstall: params.trustedSourceLinkedOfficialInstall,
    });
  if (
    shouldBypassOpenClawInstallFriction({
      source: params.source,
      trustedSourceLinkedOfficialInstall: params.trustedSourceLinkedOfficialInstall,
    })
  ) {
    return await runPolicy();
  }
  const scanRoots = await collectInstalledPackageScanRoots({
    ...(params.additionalPackageDirs
      ? { additionalPackageDirs: params.additionalPackageDirs }
      : {}),
    dependencyScanRootDir: params.dependencyScanRootDir,
    packageDir: params.packageDir,
  });
  const manifestScanRoots = await collectNonOverlappingPackageScanRoots(scanRoots);
  for (const packageDir of manifestScanRoots) {
    const dependencyBlocked = await scanPluginDependencyDenylist({
      logger: params.logger,
      packageDir,
      allowManagedNpmRootPackagePeerSymlinks: params.allowManagedNpmRootPackagePeerSymlinks,
      relativeRootDir: params.dependencyScanRootDir ?? params.packageDir,
      targetLabel: `Plugin "${params.pluginId}" installation`,
    });
    if (dependencyBlocked) {
      return dependencyBlocked;
    }
  }

  return await runPolicy();
}

export async function scanFileInstallSourceRuntime(
  params: InstallSafetyOverrides & {
    config?: OpenClawConfig;
    filePath: string;
    logger: InstallScanLogger;
    mode?: "install" | "update";
    pluginId: string;
    requestedSpecifier?: string;
    source?: InstallPolicySource;
  },
): Promise<InstallSecurityScanResult | undefined> {
  const policyResult = await runOperatorInstallPolicy({
    config: params.config,
    logger: params.logger,
    origin: { type: "plugin-file" },
    source: params.source ?? resolvePolicySource({ requestKind: "plugin-file" }),
    sourcePath: params.filePath,
    sourcePathKind: "file",
    targetName: params.pluginId,
    targetType: "plugin",
    requestKind: "plugin-file",
    requestMode: params.mode ?? "install",
    requestedSpecifier: params.requestedSpecifier,
    plugin: {
      contentType: "file",
      pluginId: params.pluginId,
      extensions: [path.basename(params.filePath)],
    },
  });
  if (policyResult?.blocked) {
    return policyResult;
  }

  const hookResult = await runBeforeInstallHook({
    config: params.config,
    logger: params.logger,
    installLabel: `Plugin file "${params.pluginId}" installation`,
    origin: "plugin-file",
    sourcePath: params.filePath,
    sourcePathKind: "file",
    targetName: params.pluginId,
    targetType: "plugin",
    requestKind: "plugin-file",
    requestMode: params.mode ?? "install",
    requestedSpecifier: params.requestedSpecifier,
    plugin: {
      contentType: "file",
      pluginId: params.pluginId,
      extensions: [path.basename(params.filePath)],
    },
  });
  return hookResult;
}

export async function preflightPluginNpmInstallPolicyRuntime(params: {
  config?: OpenClawConfig;
  logger: InstallScanLogger;
  mode?: "install" | "update";
  packageName: string;
  pluginId?: string;
  requestedSpecifier?: string;
  source?: InstallPolicySource;
  sourcePath: string;
  sourcePathKind: "file" | "directory";
}): Promise<InstallSecurityScanResult | undefined> {
  const pluginId = params.pluginId ?? params.packageName;
  return await runOperatorInstallPolicy({
    config: params.config,
    logger: params.logger,
    origin: { type: "plugin-npm", packageName: params.packageName },
    source: params.source ?? resolvePolicySource({ requestKind: "plugin-npm" }),
    sourcePath: params.sourcePath,
    sourcePathKind: params.sourcePathKind,
    targetName: pluginId,
    targetType: "plugin",
    requestKind: "plugin-npm",
    requestMode: params.mode ?? "install",
    requestedSpecifier: params.requestedSpecifier,
    plugin: {
      contentType: "package",
      pluginId,
      packageName: params.packageName,
    },
  });
}

export async function preflightPluginGitInstallPolicyRuntime(params: {
  config?: OpenClawConfig;
  logger: InstallScanLogger;
  mode?: "install" | "update";
  pluginId: string;
  requestedSpecifier?: string;
  source?: InstallPolicySource;
  sourcePath: string;
}): Promise<InstallSecurityScanResult | undefined> {
  return await runOperatorInstallPolicy({
    config: params.config,
    logger: params.logger,
    origin: { type: "plugin-git" },
    source: params.source ?? resolvePolicySource({ requestKind: "plugin-git" }),
    sourcePath: params.sourcePath,
    sourcePathKind: "directory",
    targetName: params.pluginId,
    targetType: "plugin",
    requestKind: "plugin-git",
    requestMode: params.mode ?? "install",
    requestedSpecifier: params.requestedSpecifier,
    plugin: {
      contentType: "package",
      pluginId: params.pluginId,
    },
  });
}

export async function evaluateSkillInstallPolicyRuntime(params: {
  config?: OpenClawConfig;
  workspaceDir: string;
  installId: string;
  installSpec?: SkillInstallSpec;
  logger: InstallScanLogger;
  origin: InstallPolicyOrigin;
  requestedSpecifier?: string;
  source?: InstallPolicySource;
  mode?: "install" | "update";
  skillName: string;
  sourceDir: string;
}): Promise<InstallSecurityScanResult | undefined> {
  const runPolicy = () =>
    runOperatorInstallPolicy({
      config: params.config,
      logger: params.logger,
      origin: params.origin,
      source:
        params.source ??
        resolvePolicySource({ requestKind: "skill-install", origin: params.origin }),
      sourcePath: params.sourceDir,
      sourcePathKind: "directory",
      targetName: params.skillName,
      targetType: "skill",
      requestKind: "skill-install",
      requestMode: params.mode ?? "install",
      requestedSpecifier: params.requestedSpecifier,
      skill: {
        installId: params.installId,
        ...(params.installSpec ? { installSpec: params.installSpec } : {}),
      },
    });
  const policyResult = await runPolicy();
  if (policyResult?.blocked) {
    return policyResult;
  }

  const hookResult = await runBeforeInstallHook({
    config: params.config,
    workspaceDir: params.workspaceDir,
    logger: params.logger,
    installLabel: `Skill "${params.skillName}" installation`,
    origin: formatInstallPolicyOriginForHook(params.origin),
    sourcePath: params.sourceDir,
    sourcePathKind: "directory",
    targetName: params.skillName,
    targetType: "skill",
    requestKind: "skill-install",
    requestMode: params.mode ?? "install",
    requestedSpecifier: params.requestedSpecifier,
    skill: {
      installId: params.installId,
      ...(params.installSpec ? { installSpec: params.installSpec } : {}),
    },
  });
  return hookResult;
}
/* oxlint-disable max-lines -- TODO: split this grandfathered oversized file. */
