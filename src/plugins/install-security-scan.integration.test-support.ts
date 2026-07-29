import fs from "node:fs";
import path from "node:path";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { withEnvAsync } from "../test-utils/env.js";
import {
  evaluateSkillInstallPolicyRuntime,
  scanFileInstallSourceRuntime,
} from "./install-security-scan.runtime.js";
import { makeTempDir, writePlugin } from "./loader.test-fixtures.js";

export function writeBeforeInstallBlocker(
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

export function scanInstallPayload(config: OpenClawConfig, pluginId = "payload") {
  return scanFileInstallSourceRuntime({
    config,
    filePath: path.join(makeTempDir(), `${pluginId}.js`),
    logger: {},
    pluginId,
  });
}

export function scanSkillInstall(
  config: OpenClawConfig,
  workspaceDir: string,
  skillName = "payload",
) {
  return evaluateSkillInstallPolicyRuntime({
    config,
    workspaceDir,
    installId: "node",
    logger: {},
    origin: { type: "workspace" },
    skillName,
    sourceDir: makeTempDir(),
  });
}

export function withInstallScanEnv<T>(stateDir: string, run: () => Promise<T>) {
  return withEnvAsync(
    {
      OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
      OPENCLAW_STATE_DIR: stateDir,
    },
    run,
  );
}
