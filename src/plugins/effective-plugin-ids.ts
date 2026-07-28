/** Resolves effective plugin ids from config, installed records, and activation metadata. */
import { normalizeOptionalLowercaseString } from "@openclaw/normalization-core/string-coerce";
import { sortUniqueStrings } from "@openclaw/normalization-core/string-normalization";
import {
  listExplicitlyDisabledChannelIdsForConfig,
  listPotentialConfiguredChannelIds,
} from "../channels/config-presence.js";
import { applyPluginAutoEnable } from "../config/plugin-auto-enable.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { isVitestRuntimeEnv } from "../infra/env.js";
import {
  listExplicitConfiguredChannelIdsForConfig,
  loadGatewayStartupPluginPlan,
  resolveConfiguredChannelPluginIds,
} from "./channel-plugin-ids.js";
import { normalizePluginsConfig } from "./config-state.js";
import { loadManifestMetadataSnapshot } from "./manifest-contract-eligibility.js";
import { passesManifestOwnerBasePolicy } from "./manifest-owner-policy.js";
import { normalizePluginPolicyId } from "./plugin-policy-id.js";
import type { PluginRegistryRecord } from "./plugin-registry-snapshot.js";
import { defaultSlotIdForKey } from "./slots.js";

function collectConfiguredChannelIds(
  config: OpenClawConfig,
  activationSourceConfig: OpenClawConfig,
  env: NodeJS.ProcessEnv,
): string[] {
  const disabled = new Set([
    ...listExplicitlyDisabledChannelIdsForConfig(config),
    ...listExplicitlyDisabledChannelIdsForConfig(activationSourceConfig),
  ]);
  const ids = new Set([
    ...listPotentialConfiguredChannelIds(config, env, { includePersistedAuthState: false }),
    ...listExplicitConfiguredChannelIdsForConfig(activationSourceConfig),
  ]);
  return [...ids]
    .map((channelId) => normalizeOptionalLowercaseString(channelId))
    .filter((channelId): channelId is string => {
      if (!channelId) {
        return false;
      }
      return !disabled.has(channelId);
    })
    .toSorted((left, right) => left.localeCompare(right));
}

function collectBundledChannelOwnerPluginIds(params: {
  config: OpenClawConfig;
  channelIds: readonly string[];
  env: NodeJS.ProcessEnv;
  workspaceDir?: string;
  bundledPluginsDir?: string;
}): string[] {
  const plugins = normalizePluginsConfig(params.config.plugins);
  const channelIds = new Set(
    params.channelIds
      .map((channelId) => normalizeOptionalLowercaseString(channelId))
      .filter((channelId): channelId is string => Boolean(channelId)),
  );
  if (channelIds.size === 0) {
    return [];
  }
  const env = params.bundledPluginsDir
    ? {
        ...params.env,
        OPENCLAW_BUNDLED_PLUGINS_DIR: params.bundledPluginsDir,
        ...(isVitestRuntimeEnv(params.env) || isVitestRuntimeEnv()
          ? { OPENCLAW_TEST_TRUST_BUNDLED_PLUGINS_DIR: "1" }
          : {}),
      }
    : params.env;
  const snapshot = loadManifestMetadataSnapshot({
    config: params.config,
    env,
    workspaceDir: params.workspaceDir,
  });
  const pluginIds = new Set<string>();
  for (const plugin of snapshot.plugins) {
    if (plugin.origin !== "bundled") {
      continue;
    }
    if (
      plugin.channels.some((channelId) =>
        channelIds.has(normalizeOptionalLowercaseString(channelId) ?? ""),
      )
    ) {
      const pluginId = normalizeOptionalLowercaseString(plugin.id);
      if (
        pluginId &&
        passesManifestOwnerBasePolicy({
          plugin: { id: pluginId },
          normalizedConfig: plugins,
          allowRestrictiveAllowlistBypass: true,
        })
      ) {
        pluginIds.add(pluginId);
      }
    }
  }
  return sortUniqueStrings(pluginIds);
}

/** Lists canonical plugin ids explicitly trusted through config policy or load paths. */
export function resolveExplicitEffectivePluginIds(
  config: OpenClawConfig,
  options: {
    pluginRecords?: readonly Pick<PluginRegistryRecord, "origin" | "pluginId">[];
  } = {},
): string[] {
  const plugins = normalizePluginsConfig(config.plugins);
  if (!plugins.enabled) {
    return [];
  }

  const canonicalPluginIds = new Map(
    (options.pluginRecords ?? []).map((plugin) => [
      normalizePluginPolicyId(plugin.pluginId),
      plugin.pluginId,
    ]),
  );
  const resolveCanonicalPluginId = (pluginId: string) =>
    canonicalPluginIds.get(normalizePluginPolicyId(pluginId)) ?? pluginId;
  const allowedPluginIds = new Set(plugins.allow.map(normalizePluginPolicyId));
  const passesAllowlist = (pluginId: string) =>
    allowedPluginIds.size === 0 || allowedPluginIds.has(normalizePluginPolicyId(pluginId));
  const ids = new Set(plugins.allow.map(resolveCanonicalPluginId));
  for (const [pluginId, entry] of Object.entries(plugins.entries)) {
    if (entry?.enabled === true && passesAllowlist(pluginId)) {
      ids.add(resolveCanonicalPluginId(pluginId));
    }
  }
  for (const plugin of options.pluginRecords ?? []) {
    if (plugin.origin === "config" && passesAllowlist(plugin.pluginId)) {
      ids.add(plugin.pluginId);
    }
  }
  for (const pluginId of plugins.deny) {
    const policyId = normalizePluginPolicyId(pluginId);
    for (const id of ids) {
      if (normalizePluginPolicyId(id) === policyId) {
        ids.delete(id);
      }
    }
  }
  for (const [pluginId, entry] of Object.entries(plugins.entries)) {
    if (entry?.enabled === false) {
      const policyId = normalizePluginPolicyId(pluginId);
      for (const id of ids) {
        if (normalizePluginPolicyId(id) === policyId) {
          ids.delete(id);
        }
      }
    }
  }
  return sortUniqueStrings(ids);
}

function collectSelectedContextEnginePluginIds(config: OpenClawConfig): string[] {
  const plugins = normalizePluginsConfig(config.plugins);
  if (!plugins.enabled) {
    return [];
  }
  const pluginId = plugins.slots.contextEngine;
  if (!pluginId || pluginId === defaultSlotIdForKey("contextEngine")) {
    return [];
  }
  if (plugins.deny.includes(pluginId)) {
    return [];
  }
  if (plugins.entries[pluginId]?.enabled === false) {
    return [];
  }
  return [pluginId];
}

/** Lists plugin ids that are effectively enabled for a config/discovery context. */
export function resolveEffectivePluginIds(params: {
  config: OpenClawConfig;
  env: NodeJS.ProcessEnv;
  workspaceDir?: string;
  bundledPluginsDir?: string;
}): string[] {
  const autoEnabled = applyPluginAutoEnable({
    config: params.config,
    env: params.env,
  });
  const effectiveConfig = autoEnabled.config;
  const ids = new Set(resolveExplicitEffectivePluginIds(effectiveConfig));
  for (const pluginId of collectSelectedContextEnginePluginIds(effectiveConfig)) {
    ids.add(pluginId);
  }
  const configuredChannelIds = collectConfiguredChannelIds(
    effectiveConfig,
    params.config,
    params.env,
  );
  for (const pluginId of resolveConfiguredChannelPluginIds({
    config: effectiveConfig,
    activationSourceConfig: params.config,
    workspaceDir: params.workspaceDir,
    env: params.env,
  })) {
    ids.add(pluginId);
  }
  for (const pluginId of collectBundledChannelOwnerPluginIds({
    config: effectiveConfig,
    channelIds: configuredChannelIds,
    env: params.env,
    workspaceDir: params.workspaceDir,
    ...(params.bundledPluginsDir ? { bundledPluginsDir: params.bundledPluginsDir } : {}),
  })) {
    ids.add(pluginId);
  }
  for (const pluginId of loadGatewayStartupPluginPlan({
    config: effectiveConfig,
    activationSourceConfig: params.config,
    workspaceDir: params.workspaceDir,
    env: params.env,
  }).pluginIds) {
    ids.add(pluginId);
  }
  return sortUniqueStrings(ids);
}
