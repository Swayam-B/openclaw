import { createHash } from "node:crypto";
import { stableStringify } from "../agents/stable-stringify.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { resolveGlobalSingleton } from "../shared/global-singleton.js";
import { normalizePluginsConfig } from "./config-state.js";
import { normalizePluginPolicyId } from "./plugin-policy-id.js";
import type { PluginRegistry } from "./registry-types.js";

const registryPluginEntryFingerprints = resolveGlobalSingleton<
  WeakMap<PluginRegistry, Map<string, string>>
>(Symbol.for("openclaw.pluginRegistryPluginEntryFingerprints"), () => new WeakMap());

function fingerprintPluginEntry(config: OpenClawConfig, pluginId: string): string {
  const normalizedId = normalizePluginPolicyId(pluginId);
  const entry = normalizePluginsConfig(config.plugins).entries[normalizedId];
  return createHash("sha256").update(stableStringify(entry)).digest("hex");
}

export function recordPluginRegistryConfigProvenance(params: {
  registry: PluginRegistry;
  config: OpenClawConfig;
  pluginId: string;
}): void {
  let fingerprints = registryPluginEntryFingerprints.get(params.registry);
  if (!fingerprints) {
    fingerprints = new Map();
    registryPluginEntryFingerprints.set(params.registry, fingerprints);
  }
  fingerprints.set(
    normalizePluginPolicyId(params.pluginId),
    fingerprintPluginEntry(params.config, params.pluginId),
  );
}

export function pluginRegistryConfigMatches(params: {
  registry: PluginRegistry;
  config: OpenClawConfig;
  pluginId: string;
}): boolean {
  const pluginId = normalizePluginPolicyId(params.pluginId);
  return (
    registryPluginEntryFingerprints.get(params.registry)?.get(pluginId) ===
    fingerprintPluginEntry(params.config, pluginId)
  );
}
