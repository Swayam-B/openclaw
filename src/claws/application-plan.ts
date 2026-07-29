import { createHash } from "node:crypto";
import { stableStringify } from "../agents/stable-stringify.js";
import type {
  ClawAddCapabilityChange,
  ClawAddPlanAction,
  ClawDiagnostic,
  ClawExtensionPlan,
  ClawOpenClawExtension,
  ClawOpenClawProfile,
  ClawPackage,
  ClawPackagePreflight,
  ClawPackagePreflightResult,
} from "./types.js";

export function clawProfileExtensionPackages(
  profile: ClawOpenClawProfile | undefined,
): ClawPackage[] {
  if (profile?.schemaVersion !== 2) {
    return [];
  }
  return profile.extensions.map((extension) => ({
    kind: "plugin",
    source: extension.source,
    ref: extension.ref,
    version: extension.version,
  }));
}

function blocker(code: string, path: string, message: string): ClawDiagnostic {
  return { level: "error", code, phase: "plan", path, message };
}

function extensionCapabilityChange(params: {
  extension: ClawOpenClawExtension;
  preflight: ClawPackagePreflightResult;
}): ClawAddCapabilityChange {
  const effect = {
    id: params.extension.id,
    source: params.extension.source,
    ref: params.extension.ref,
    version: params.extension.version,
    expectedFormat: params.extension.format,
    detectedFormat: params.preflight.detectedFormat ?? "unresolved",
    integrity: params.preflight.integrity ?? "unresolved",
    mapped: params.preflight.mapped ?? [],
    unavailable: params.preflight.unavailable ?? [],
    adapterIdentity: params.preflight.adapterIdentity ?? "unresolved",
    ...(params.preflight.installId ? { installId: params.preflight.installId } : {}),
    ...(params.preflight.warning ? { riskWarning: params.preflight.warning } : {}),
  };
  const change = {
    kind: "package" as const,
    id: `extension:${params.extension.id}`,
    path: `openclaw.extensions.${params.extension.id}`,
    action: "install" as const,
    reason: "The OpenClaw profile declares downloadable extension content or executable code.",
    effect,
  };
  return {
    ...change,
    classification: "escalation",
    requiresDistinctConsent: true,
    digest: `sha256:${createHash("sha256").update(stableStringify(effect)).digest("hex")}`,
  };
}

export async function planClawExtensions(params: {
  extensions: ClawOpenClawExtension[];
  workspace: string;
  packagePreflight?: ClawPackagePreflight;
}): Promise<{
  extensions: ClawExtensionPlan[];
  actions: ClawAddPlanAction[];
  capabilityChanges: ClawAddCapabilityChange[];
  blockers: ClawDiagnostic[];
}> {
  const extensions: ClawExtensionPlan[] = [];
  const actions: ClawAddPlanAction[] = [];
  const capabilityChanges: ClawAddCapabilityChange[] = [];
  const blockers: ClawDiagnostic[] = [];

  for (const [index, extension] of params.extensions.entries()) {
    const preflight: ClawPackagePreflightResult = params.packagePreflight
      ? await params.packagePreflight(
          {
            kind: "plugin",
            source: extension.source,
            ref: extension.ref,
            version: extension.version,
          },
          params.workspace,
        )
      : {
          ok: false as const,
          code: "package_install_unavailable",
          message: "Extension preflight is unavailable.",
        };
    const formatMismatch =
      preflight.ok && preflight.detectedFormat !== extension.format
        ? blocker(
            "extension_format_mismatch",
            `$.metadata.openclaw.config.extensions[${index}].format`,
            `Extension ${JSON.stringify(extension.id)} declares format ${JSON.stringify(extension.format)}, but the canonical plugin detector found ${JSON.stringify(preflight.detectedFormat ?? "unknown")}.`,
          )
        : undefined;
    const diagnostic = !preflight.ok
      ? blocker(
          preflight.code ?? "extension_preflight_failed",
          `$.metadata.openclaw.config.extensions[${index}]`,
          preflight.message ?? "Extension preflight failed.",
        )
      : formatMismatch;
    if (diagnostic) {
      blockers.push(diagnostic);
    }
    const extensionPlan: ClawExtensionPlan = {
      ...extension,
      ...(preflight.detectedFormat ? { detectedFormat: preflight.detectedFormat } : {}),
      ...(preflight.integrity ? { integrity: preflight.integrity } : {}),
      ...(preflight.installId ? { installId: preflight.installId } : {}),
      ...(preflight.action ? { ownerAction: preflight.action } : {}),
      mapped: preflight.mapped ?? [],
      unavailable: preflight.unavailable ?? [],
      ...(preflight.adapterIdentity ? { adapterIdentity: preflight.adapterIdentity } : {}),
      blocked: !preflight.ok || Boolean(formatMismatch),
    };
    extensions.push(extensionPlan);
    actions.push({
      kind: "package",
      id: `extension:${extension.id}`,
      action: "install",
      target: `${extension.source}:${extension.ref}@${extension.version}`,
      ...(preflight.integrity ? { digest: preflight.integrity } : {}),
      details: {
        ...extensionPlan,
        expectedState: !preflight.ok
          ? "unresolved"
          : preflight.action === "reuse"
            ? "present-exact"
            : "absent",
        ...(preflight.warning ? { riskWarning: preflight.warning } : {}),
      },
      blocked: extensionPlan.blocked,
      ...(diagnostic ? { reason: diagnostic.message } : {}),
    });
    capabilityChanges.push(extensionCapabilityChange({ extension, preflight }));
  }

  return { extensions, actions, capabilityChanges, blockers };
}
