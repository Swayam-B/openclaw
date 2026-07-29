import type { PluginBundleFormat } from "./manifest-types.js";

export type PluginArtifactFormat = "openclaw" | PluginBundleFormat;

export type PluginInstallArtifactInspection = {
  format: PluginArtifactFormat;
  mapped: string[];
  unavailable: string[];
};

const MAPPED_BUNDLE_CAPABILITIES: Record<PluginBundleFormat, ReadonlySet<string>> = {
  codex: new Set(["hooks", "mcpServers", "skills"]),
  claude: new Set(["commands", "lspServers", "mcpServers", "settings", "skills"]),
  cursor: new Set(["commands", "mcpServers", "skills"]),
};

export function inspectNativePluginArtifact(): PluginInstallArtifactInspection {
  return { format: "openclaw", mapped: ["plugin"], unavailable: [] };
}

export function inspectBundlePluginArtifact(params: {
  format: PluginBundleFormat;
  capabilities: Iterable<string>;
}): PluginInstallArtifactInspection {
  const supported = MAPPED_BUNDLE_CAPABILITIES[params.format];
  const capabilities = [...new Set(params.capabilities)].toSorted();
  return {
    format: params.format,
    mapped: capabilities.filter((capability) => supported.has(capability)),
    unavailable: capabilities.filter((capability) => !supported.has(capability)),
  };
}
