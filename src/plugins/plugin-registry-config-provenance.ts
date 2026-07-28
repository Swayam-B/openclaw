import { createHash } from "node:crypto";
import { stableStringify } from "../agents/stable-stringify.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { resolveGlobalSingleton } from "../shared/global-singleton.js";
import { applyTestPluginDefaults } from "./config-state.js";
import { normalizePluginPolicyId } from "./plugin-policy-id.js";
import type { PluginRegistry } from "./registry-types.js";

const registryPluginConfigFingerprints = resolveGlobalSingleton<
  WeakMap<PluginRegistry, Map<string, string>>
>(Symbol.for("openclaw.pluginRegistryPluginApiConfigFingerprints"), () => new WeakMap());

function fingerprintPluginApiConfig(config: OpenClawConfig): string {
  return createHash("sha256")
    .update(stableStringify(applyTestPluginDefaults(config)))
    .digest("hex");
}

export function recordPluginRegistryConfigProvenance(params: {
  registry: PluginRegistry;
  config: OpenClawConfig;
  pluginId: string;
}): void {
  let fingerprints = registryPluginConfigFingerprints.get(params.registry);
  if (!fingerprints) {
    fingerprints = new Map();
    registryPluginConfigFingerprints.set(params.registry, fingerprints);
  }
  fingerprints.set(
    normalizePluginPolicyId(params.pluginId),
    fingerprintPluginApiConfig(params.config),
  );
}

export function pluginRegistryConfigMatches(params: {
  registry: PluginRegistry;
  config: OpenClawConfig;
  pluginId: string;
}): boolean {
  const pluginId = normalizePluginPolicyId(params.pluginId);
  return (
    registryPluginConfigFingerprints.get(params.registry)?.get(pluginId) ===
    fingerprintPluginApiConfig(params.config)
  );
}
