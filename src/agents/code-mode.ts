/**
 * Host-side Code Mode controller for isolated QuickJS execution with bridged
 * tool search/call/yield support.
 */
import { Type } from "typebox";
import { getAgentToolExecutionContext } from "../../packages/agent-core/src/tool-execution-context.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type { HookContext } from "./agent-tools.before-tool-call.js";
import {
  codeModeReplayIdForToolCall,
  runBridgeRequest,
  setCodeModeSwarmDepsForTest,
} from "./code-mode-bridge.js";
import {
  CODE_MODE_EXEC_TOOL_NAME,
  CODE_MODE_WAIT_TOOL_NAME,
  isCodeModeControlTool,
  markCodeModeControlTool,
} from "./code-mode-control-tools.js";
import { runExec, runWait } from "./code-mode-execution.js";
import { createHeadlessAbortScope, runCodeModeScriptHeadless } from "./code-mode-headless.js";
import { describeCodeModeNamespacesForPrompt } from "./code-mode-namespaces.js";
import {
  codeModeRuntimeTesting,
  isCodeModeEngagedForModel,
  readCode,
  readRunId,
  resolveCodeModeConfig,
  resolveCodeModeHeadlessConfig,
} from "./code-mode-runtime.js";
import { activeRuns, removeExpiredRuns, resumingRunIds } from "./code-mode-state.js";
import {
  normalizeCodeModeTimeoutResult,
  normalizeCodeModeWorkerResult,
  resolveCodeModeWorkerUrl,
  runCodeModeWorker,
  CodeModeHeadlessAbortError,
  CodeModeHeadlessTimeoutError,
} from "./code-mode-worker.js";
import type { AgentToolUpdateCallback } from "./runtime/index.js";
import { optionalStringEnum } from "./schema/typebox.js";
import type { ToolDefinition } from "./sessions/index.js";
import { resolveSwarmConfig } from "./swarm-config.js";
import { isDirectVisibleCatalogTool } from "./tool-search-catalog.js";
import {
  addClientToolsToToolCatalog,
  applyToolCatalogCompaction,
  compactToolSearchCatalogEntry,
  TOOL_CALL_RAW_TOOL_NAME,
  TOOL_DESCRIBE_RAW_TOOL_NAME,
  TOOL_SEARCH_CODE_MODE_TOOL_NAME,
  TOOL_SEARCH_RAW_TOOL_NAME,
  type ToolSearchCatalogEntry,
  type ToolSearchCatalogRef,
  type ToolSearchToolContext,
} from "./tool-search.js";
import { jsonResult, type AnyAgentTool } from "./tools/common.js";

export { CODE_MODE_EXEC_TOOL_NAME, CODE_MODE_WAIT_TOOL_NAME };
export {
  CodeModeHeadlessAbortError,
  CodeModeHeadlessTimeoutError,
  isCodeModeEngagedForModel,
  runCodeModeScriptHeadless,
  resolveCodeModeConfig,
};
export type { CodeModeFailureCode, CodeModeHeadlessResult } from "./code-mode-runtime.js";

type CodeModeToolContext = ToolSearchToolContext;

const MAX_CODE_MODE_METHOD_INDEX_CHARS = 1_600;
const MAX_CODE_MODE_OUTPUT_HINT_CHARS = 96;
const CODE_MODE_DIRECT_METHOD_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
const CODE_MODE_RESERVED_METHOD_NAMES = new Set([
  "search",
  "describe",
  "call",
  "callValue",
  CODE_MODE_EXEC_TOOL_NAME,
  CODE_MODE_WAIT_TOOL_NAME,
]);
const CODE_MODE_METHOD_INDEX_HEADING =
  "Enabled direct methods inside code (await calls; short declared outputs follow `->`):";

function codeModeMethodIndexFooter(included: number, total: number): string {
  const omitted = total - included;
  return omitted > 0
    ? `${omitted} more direct methods omitted. Discover them with ALL_TOOLS or tools.search(query).`
    : "";
}

function renderCodeModeMethodIndex(lines: readonly string[], total: number): string {
  const footer = codeModeMethodIndexFooter(lines.length, total);
  return [CODE_MODE_METHOD_INDEX_HEADING, ...lines, ...(footer ? ["", footer] : [])].join("\n");
}

function collectCodeModeDirectCatalogEntries(
  catalog: readonly ToolSearchCatalogEntry[],
): ToolSearchCatalogEntry[] {
  const nameCounts = new Map<string, number>();
  for (const entry of catalog) {
    if (!CODE_MODE_DIRECT_METHOD_PATTERN.test(entry.name)) {
      continue;
    }
    nameCounts.set(entry.name, (nameCounts.get(entry.name) ?? 0) + 1);
  }
  return catalog.filter(
    (entry) =>
      entry.source === "openclaw" &&
      nameCounts.get(entry.name) === 1 &&
      !CODE_MODE_RESERVED_METHOD_NAMES.has(entry.name),
  );
}

export function collectCodeModeDirectToolNames(
  catalog: readonly ToolSearchCatalogEntry[],
): Set<string> {
  return new Set(collectCodeModeDirectCatalogEntries(catalog).map((entry) => entry.name));
}

function formatCodeModeMethodIndex(catalog: readonly ToolSearchCatalogEntry[]): string {
  const lines = collectCodeModeDirectCatalogEntries(catalog)
    .map((entry) => compactToolSearchCatalogEntry(entry))
    .map((entry) => {
      const input = entry.input && entry.input !== "unknown" ? entry.input : "input?: unknown";
      const output =
        entry.output && entry.output.length <= MAX_CODE_MODE_OUTPUT_HINT_CHARS
          ? ` -> ${entry.output}`
          : "";
      return {
        line: `- tools.${entry.name}(${input})${output}`,
        name: entry.name,
      };
    })
    // Prefer breadth: short callable signatures teach more exact method names
    // than a few verbose result contracts under the same model-facing budget.
    .toSorted((a, b) => a.line.length - b.line.length || a.name.localeCompare(b.name))
    .map((entry) => entry.line);
  if (lines.length === 0) {
    return "";
  }
  const fullIndex = renderCodeModeMethodIndex(lines, lines.length);
  if (fullIndex.length <= MAX_CODE_MODE_METHOD_INDEX_CHARS) {
    return fullIndex;
  }

  // Keep the signature budget deterministic while skipping pathological lines.
  // Every omitted method remains available on `tools` and discoverable at runtime.
  const included: string[] = [];
  let includedLineLength = 0;
  for (const line of lines) {
    const candidateLineLength = includedLineLength + 1 + line.length;
    const candidateLength =
      CODE_MODE_METHOD_INDEX_HEADING.length +
      candidateLineLength +
      2 +
      codeModeMethodIndexFooter(included.length + 1, lines.length).length;
    if (candidateLength <= MAX_CODE_MODE_METHOD_INDEX_CHARS) {
      included.push(line);
      includedLineLength = candidateLineLength;
    }
  }
  return renderCodeModeMethodIndex(included, lines.length);
}

function createCodeModeExecDescription(
  ctx: CodeModeToolContext,
  catalog?: readonly ToolSearchCatalogEntry[],
): string {
  const namespacePrompt = describeCodeModeNamespacesForPrompt(catalog);
  // A known run catalog with neither MCP nor swarm has no virtual API files.
  const catalogKnown = catalog !== undefined;
  const hasMcp = catalog?.some((entry) => entry.source === "mcp") ?? false;
  const swarmEnabled = resolveSwarmConfig(ctx.runtimeConfig ?? ctx.config, ctx.agentId).enabled;
  const apiGuidance =
    !catalogKnown || hasMcp || swarmEnabled
      ? " Read TypeScript-style declaration files with `API.list(prefix?)` and `API.read(path)`."
      : "";
  const mcpGuidance =
    !catalogKnown || hasMcp ? " MCP tools are available only through the `MCP` namespace." : "";
  const swarmGuidance = swarmEnabled
    ? " Swarm globals `agents.run`, `phase`, and `log` are available; read `agents.d.ts` for types and orchestration idioms."
    : "";
  const nodesGuidance =
    "\n- nodes: paired Gateway nodes; nodes.list(), (await nodes.get(id)).invoke(command, params)\n";
  const skillsGuidance = ctx.codeModeSkills?.length
    ? " Skills are available through the async `skills` global: use `await skills.list()` and `await skills.read(name)`."
    : "";
  const methodIndex = catalog ? formatCodeModeMethodIndex(catalog) : "";
  return (
    'Run JavaScript or TypeScript in isolated OpenClaw code mode. Explicitly `return` the final value; a trailing guest tool call is returned automatically. Prefer enabled direct methods on `tools`, for example `return await tools.read({ path: "notes.txt" });`. Use workspace-relative paths; never prefix them with `/workspace`. Await dependent calls in order and use Promise.all only for independent work. If a direct method is unavailable, find the exact id with ALL_TOOLS or `await tools.search(query)`, then call `tools.callValue(id, args)`. Never invent or transform ids. If a result shape is unknown, return the raw value instead of guessing fields. Nested calls keep normal policy and approvals. Node.js modules, shell source, `require`, and `import` are unavailable.' +
    apiGuidance +
    mcpGuidance +
    swarmGuidance +
    nodesGuidance +
    skillsGuidance +
    (namespacePrompt ? `\n\n${namespacePrompt}` : "") +
    (methodIndex ? `\n\n${methodIndex}` : "")
  );
}

export function createCodeModeTools(ctx: CodeModeToolContext): AnyAgentTool[] {
  const execTool = markCodeModeControlTool({
    name: CODE_MODE_EXEC_TOOL_NAME,
    label: "exec",
    description: createCodeModeExecDescription(ctx),
    parameters: Type.Object({
      // `command` stays runtime-only for hook compatibility. Requiring the sole
      // model-facing field prevents schema-valid empty calls from constrained models.
      code: Type.String({
        description:
          "Required JavaScript or TypeScript. Call enabled tools through `tools`; return the final value when practical.",
      }),
      language: optionalStringEnum(["javascript", "typescript"] as const, {
        description: "Defaults to javascript.",
      }),
      restartSafe: Type.Optional(
        Type.Boolean({
          description: "Only for workflows whose nested calls are all explicitly replay-safe.",
        }),
      ),
    }),
    execute: async (
      toolCallId: string,
      args: unknown,
      signal?: AbortSignal,
      onUpdate?: AgentToolUpdateCallback,
    ) => {
      const input = readCode(args);
      const executionContext = getAgentToolExecutionContext();
      return jsonResult(
        normalizeCodeModeTimeoutResult(
          await runExec({
            toolCallId,
            ctx,
            code: input.code,
            assistantTurnId:
              executionContext?.assistantMessage.responseId?.trim() ||
              executionContext?.assistantMessage.turnId?.trim(),
            language: input.language,
            restartSafe: ctx.forceRestartSafeTools === true || input.restartSafe,
            signal,
            onUpdate,
          }),
        ),
      );
    },
  } as AnyAgentTool);
  const waitTool = markCodeModeControlTool({
    name: CODE_MODE_WAIT_TOOL_NAME,
    label: "wait",
    hideFromChannelProgress: true,
    description: "Resume a suspended OpenClaw code mode run returned by exec.",
    parameters: Type.Object({
      runId: Type.String({ description: "Code mode run id returned by exec." }),
    }),
    execute: async (
      toolCallId: string,
      args: unknown,
      signal?: AbortSignal,
      onUpdate?: AgentToolUpdateCallback,
    ) =>
      jsonResult(
        normalizeCodeModeTimeoutResult(
          await runWait({
            toolCallId,
            ctx,
            runId: readRunId(args),
            signal,
            onUpdate,
          }),
        ),
      ),
  } as AnyAgentTool);
  return [execTool, waitTool];
}

/** Compact normal tools behind Code Mode exec/wait controls. */
export function applyCodeModeCatalog(params: {
  tools: AnyAgentTool[];
  config?: OpenClawConfig;
  sessionId?: string;
  sessionKey?: string;
  agentId?: string;
  runId?: string;
  catalogRef?: ToolSearchCatalogRef;
  toolHookContext?: HookContext;
  directToolNames?: Iterable<string>;
  codeModeSkills?: CodeModeToolContext["codeModeSkills"];
}) {
  const config = resolveCodeModeConfig(params.config, params.agentId);
  // Engagement (including "auto" per-model resolution) is decided by the run
  // gates before this is called; only a hard `false` may disable compaction.
  if (config.enabled === false) {
    return applyToolCatalogCompaction({
      ...params,
      enabled: false,
      isVisibleControlTool: isCodeModeControlTool,
    });
  }
  const tools = params.tools.filter(
    (tool) =>
      isCodeModeControlTool(tool) ||
      (tool.name !== TOOL_SEARCH_CODE_MODE_TOOL_NAME &&
        tool.name !== TOOL_SEARCH_RAW_TOOL_NAME &&
        tool.name !== TOOL_DESCRIBE_RAW_TOOL_NAME &&
        tool.name !== TOOL_CALL_RAW_TOOL_NAME),
  );
  const directToolNames = new Set(params.directToolNames);
  const compacted = applyToolCatalogCompaction({
    ...params,
    tools,
    enabled: true,
    isVisibleControlTool: isCodeModeControlTool,
    // Code mode never exposes core shell/file tools just because structured
    // search does; only explicitly required, trusted direct tools may remain.
    isVisibleCatalogTool: (tool) =>
      directToolNames.has(tool.name) && isDirectVisibleCatalogTool(tool, directToolNames),
    shouldCatalogTool: (tool) => !isCodeModeControlTool(tool),
  });
  // Only the catalog ref reflects the freshly compacted run catalog. Without it
  // the real catalog is registered under session keys and resolved later, so
  // keep the catalog "unknown" (undefined) rather than an empty array that would
  // wrongly strip MCP/namespace guidance from the exec description.
  const visibleCatalog = params.catalogRef?.current?.entries;
  for (const tool of compacted.tools) {
    if (tool.name === CODE_MODE_EXEC_TOOL_NAME) {
      tool.description = createCodeModeExecDescription(
        {
          config: params.config,
          runtimeConfig: params.config,
          agentId: params.agentId,
          sessionId: params.sessionId,
          sessionKey: params.sessionKey,
          runId: params.runId,
          catalogRef: params.catalogRef,
          codeModeSkills: params.codeModeSkills,
        },
        visibleCatalog,
      );
    }
  }
  return compacted;
}

/** Move client-side tool definitions into the active Code Mode catalog. */
export function addClientToolsToCodeModeCatalog(params: {
  tools: ToolDefinition[];
  config?: OpenClawConfig;
  sessionId?: string;
  sessionKey?: string;
  agentId?: string;
  runId?: string;
  catalogRef?: ToolSearchCatalogRef;
}) {
  return addClientToolsToToolCatalog({
    ...params,
    // Callers gate on run engagement; "auto" counts as enabled here.
    enabled: resolveCodeModeConfig(params.config, params.agentId).enabled !== false,
  });
}

/** Test-only hooks and state accessors for Code Mode worker orchestration. */
const testing = {
  activeRuns,
  resumingRunIds,
  codeModeReplayIdForToolCall,
  removeExpiredRuns,
  runBridgeRequest,
  createHeadlessAbortScope,
  normalizeCodeModeWorkerResult,
  runCodeModeWorker,
  resolveCodeModeHeadlessConfig,
  resolveCodeModeWorkerUrl,
  getTypescriptRuntimePromise: codeModeRuntimeTesting.getTypescriptRuntimePromise,
  setTypescriptRuntimeForTest: codeModeRuntimeTesting.setTypescriptRuntimeForTest,
  setSwarmDepsForTest: setCodeModeSwarmDepsForTest,
};

if (process.env.VITEST || process.env.NODE_ENV === "test") {
  (globalThis as Record<PropertyKey, unknown>)[Symbol.for("openclaw.codeModeTestApi")] = testing;
}
