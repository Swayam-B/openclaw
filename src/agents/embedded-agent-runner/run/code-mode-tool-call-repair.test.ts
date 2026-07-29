import { describe, expect, it, vi } from "vitest";
import { wrapStreamFnTranslateCodeModeGuestToolCalls } from "./code-mode-tool-call-repair.js";

function createFakeStream(params: { events?: unknown[]; resultMessage: unknown }) {
  return {
    async result() {
      return params.resultMessage;
    },
    [Symbol.asyncIterator]() {
      return (async function* () {
        for (const event of params.events ?? []) {
          yield event;
        }
      })();
    },
  };
}

async function invoke(params: { events?: unknown[]; resultMessage: unknown }) {
  const baseFn = vi.fn(() => createFakeStream(params));
  const wrapped = wrapStreamFnTranslateCodeModeGuestToolCalls(
    baseFn as never,
    new Set(["read", "write"]),
  );
  const stream = await Promise.resolve(wrapped({} as never, {} as never, {} as never));
  for await (const event of stream) {
    void event;
  }
  return await stream.result();
}

describe("Code Mode outer guest tool-call repair", () => {
  it.each(["read", "tools.read", "tools/read"])(
    "translates exact guest method %s into exec",
    async (name) => {
      const message = {
        role: "assistant",
        content: [{ type: "toolCall", name, arguments: { path: "facts.txt" } }],
      };

      await expect(invoke({ resultMessage: message })).resolves.toEqual({
        role: "assistant",
        content: [
          {
            type: "toolCall",
            name: "exec",
            arguments: {
              code: 'return await tools["read"](JSON.parse("{\\"path\\":\\"facts.txt\\"}"));',
            },
          },
        ],
      });
    },
  );

  it("waits for tool-call completion before translating streamed projections", async () => {
    const partialCall = {
      type: "toolCall",
      name: "tools.write",
      arguments: {},
    };
    const streamedCall = {
      type: "toolCall",
      name: "tools.write",
      arguments: { path: "result.txt", content: "ok" },
    };
    const endMessageCall = structuredClone(streamedCall);
    const finalCall = structuredClone(streamedCall);
    await invoke({
      events: [
        { type: "toolcall_delta", partial: { content: [partialCall] } },
        {
          type: "toolcall_end",
          toolCall: streamedCall,
          message: { content: [endMessageCall] },
        },
      ],
      resultMessage: { role: "assistant", content: [finalCall] },
    });

    expect(partialCall).toEqual({
      type: "toolCall",
      name: "tools.write",
      arguments: {},
    });
    const translated = {
      type: "toolCall",
      name: "exec",
      arguments: {
        code: 'return await tools["write"](JSON.parse("{\\"path\\":\\"result.txt\\",\\"content\\":\\"ok\\"}"));',
      },
    };
    expect(streamedCall).toEqual(translated);
    expect(endMessageCall).toEqual(translated);
    expect(finalCall).toEqual(translated);
  });

  it("never translates the outer Code Mode controls", async () => {
    const message = {
      role: "assistant",
      content: [
        {
          type: "toolCall",
          name: "exec",
          arguments: { code: 'return await tools["read"]({"path":"facts.txt"});' },
        },
      ],
    };
    const baseFn = vi.fn(() => createFakeStream({ resultMessage: message }));
    const wrapped = wrapStreamFnTranslateCodeModeGuestToolCalls(
      baseFn as never,
      new Set(["read", "exec"]),
    );
    const stream = await Promise.resolve(wrapped({} as never, {} as never, {} as never));

    await expect(stream.result()).resolves.toBe(message);
    expect(message.content[0]?.arguments).toEqual({
      code: 'return await tools["read"]({"path":"facts.txt"});',
    });
  });

  it("preserves own __proto__ keys as JSON data", async () => {
    const argumentsWithProto = JSON.parse(
      '{"__proto__":{"safe":true},"nested":{"__proto__":"value"}}',
    );
    const message = {
      role: "assistant",
      content: [{ type: "toolCall", name: "read", arguments: argumentsWithProto }],
    };

    const result = await invoke({ resultMessage: message });
    const code = (result as { content: Array<{ arguments: { code: string } }> }).content[0]
      ?.arguments.code;

    expect(code).toBe(
      'return await tools["read"](JSON.parse("{\\"__proto__\\":{\\"safe\\":true},\\"nested\\":{\\"__proto__\\":\\"value\\"}}"));',
    );
  });

  it.each([
    { name: "tools.unknown", arguments: {} },
    { name: "tools.read.extra", arguments: {} },
    { name: "read", arguments: "fragment" },
    { name: "exec", arguments: { code: "return 1;" } },
  ])("leaves unsupported calls unchanged: $name", async (toolCall) => {
    const message = { role: "assistant", content: [{ type: "toolCall", ...toolCall }] };
    const expected = structuredClone(message);

    await expect(invoke({ resultMessage: message })).resolves.toEqual(expected);
  });
});
