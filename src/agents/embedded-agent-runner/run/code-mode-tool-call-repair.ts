/**
 * Repairs small-model calls that copy a Code Mode guest method into the outer
 * provider tool channel instead of calling `exec`.
 */
import { visitObjectContentBlocks } from "../../../shared/message-content-blocks.js";
import {
  CODE_MODE_EXEC_TOOL_NAME,
  CODE_MODE_WAIT_TOOL_NAME,
} from "../../code-mode-control-tools.js";
import type { StreamFn } from "../../runtime/index.js";
import { isRunnerToolCallBlockType } from "./attempt.tool-call-block-type.js";
import { wrapStreamObjectEvents } from "./stream-wrapper.js";

const MAX_TRANSLATED_ARGUMENT_CHARS = 64_000;
const GUEST_TOOL_PREFIX_PATTERN = /^tools[./]([A-Za-z_$][A-Za-z0-9_$]*)$/u;

type AssistantStream = Awaited<ReturnType<StreamFn>>;

function resolveGuestToolName(
  rawName: string,
  guestToolNames: ReadonlySet<string>,
): string | undefined {
  const trimmed = rawName.trim();
  if (trimmed === CODE_MODE_EXEC_TOOL_NAME || trimmed === CODE_MODE_WAIT_TOOL_NAME) {
    return undefined;
  }
  const prefixed = GUEST_TOOL_PREFIX_PATTERN.exec(trimmed)?.[1];
  const candidate = prefixed ?? trimmed;
  return guestToolNames.has(candidate) ? candidate : undefined;
}

function serializeGuestToolArguments(value: unknown): string | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  try {
    const serialized = JSON.stringify(value);
    return serialized.length <= MAX_TRANSLATED_ARGUMENT_CHARS ? serialized : undefined;
  } catch {
    return undefined;
  }
}

function translateCodeModeGuestToolCall(block: unknown, guestToolNames: ReadonlySet<string>): void {
  if (!block || typeof block !== "object") {
    return;
  }
  const toolCall = block as {
    type?: unknown;
    name?: unknown;
    arguments?: unknown;
    input?: unknown;
  };
  if (!isRunnerToolCallBlockType(toolCall.type) || typeof toolCall.name !== "string") {
    return;
  }
  const guestToolName = resolveGuestToolName(toolCall.name, guestToolNames);
  if (!guestToolName) {
    return;
  }
  const rawArguments = toolCall.arguments ?? toolCall.input;
  const serializedArguments = serializeGuestToolArguments(rawArguments);
  if (!serializedArguments) {
    return;
  }
  const translatedArguments = {
    code: `return await tools[${JSON.stringify(guestToolName)}](JSON.parse(${JSON.stringify(serializedArguments)}));`,
  };
  toolCall.name = "exec";
  toolCall.arguments = translatedArguments;
  if ("input" in toolCall) {
    toolCall.input = translatedArguments;
  }
}

function translateCodeModeGuestToolCalls(
  message: unknown,
  guestToolNames: ReadonlySet<string>,
): void {
  visitObjectContentBlocks(message, (block) => {
    translateCodeModeGuestToolCall(block, guestToolNames);
  });
}

function wrapStreamTranslateCodeModeGuestToolCalls(
  stream: AssistantStream,
  guestToolNames: ReadonlySet<string>,
): AssistantStream {
  const originalResult = stream.result.bind(stream);
  stream.result = async () => {
    const message = await originalResult();
    translateCodeModeGuestToolCalls(message, guestToolNames);
    return message;
  };
  wrapStreamObjectEvents(stream, (event) => {
    if (event.type !== "toolcall_end") {
      return;
    }
    translateCodeModeGuestToolCall(event.toolCall, guestToolNames);
    translateCodeModeGuestToolCalls(event.message, guestToolNames);
  });
  return stream;
}

export function wrapStreamFnTranslateCodeModeGuestToolCalls(
  baseFn: StreamFn,
  guestToolNames?: ReadonlySet<string>,
): StreamFn {
  if (!guestToolNames || guestToolNames.size === 0) {
    return baseFn;
  }
  return (model, context, streamOptions) => {
    const maybeStream = baseFn(model, context, streamOptions);
    if (maybeStream && typeof maybeStream === "object" && "then" in maybeStream) {
      return Promise.resolve(maybeStream).then((stream) =>
        wrapStreamTranslateCodeModeGuestToolCalls(stream, guestToolNames),
      );
    }
    return wrapStreamTranslateCodeModeGuestToolCalls(maybeStream, guestToolNames);
  };
}
