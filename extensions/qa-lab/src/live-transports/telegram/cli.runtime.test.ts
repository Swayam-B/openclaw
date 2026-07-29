import { afterEach, describe, expect, it, vi } from "vitest";

const runQaFlowSuiteFromRuntime = vi.hoisted(() => vi.fn());

vi.mock("../../suite-launch.runtime.js", () => ({ runQaFlowSuiteFromRuntime }));

import { runQaTelegramSuite } from "./cli.runtime.js";

afterEach(() => {
  vi.restoreAllMocks();
  runQaFlowSuiteFromRuntime.mockReset();
});

describe("Telegram QA CLI runtime", () => {
  it("lists only scenarios accepted by its flow runner", async () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await runQaTelegramSuite({
      listScenarios: true,
      providerMode: "mock-openai",
      repoRoot: process.cwd(),
    });

    const output = write.mock.calls.map(([chunk]) => String(chunk)).join("");
    expect(output).toContain("channel-message-flows\tdefault\t");
    expect(output).not.toContain("telegram-startup-getme-live");
    expect(runQaFlowSuiteFromRuntime).not.toHaveBeenCalled();
  });

  it("keeps script scenarios out of the default flow-suite invocation", async () => {
    runQaFlowSuiteFromRuntime.mockResolvedValue({
      reportPath: "/tmp/telegram-report.md",
      summaryPath: "/tmp/telegram-summary.json",
    });
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await runQaTelegramSuite({
      allowFailures: true,
      providerMode: "mock-openai",
      repoRoot: process.cwd(),
    });

    expect(runQaFlowSuiteFromRuntime).toHaveBeenCalledWith(
      expect.objectContaining({
        scenarioIds: expect.not.arrayContaining(["telegram-startup-getme-live"]),
      }),
    );
  });
});
