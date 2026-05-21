#!/usr/bin/env node
import { readFileSync } from "node:fs";
import {
  createPalette,
  formatToolBrief,
  normalizeTools,
  type PaletteOptions,
  type PaletteResult
} from "./index.js";

interface CliArgs {
  file?: string;
  task?: string;
  json: boolean;
  brief: boolean;
  includeRisky: boolean;
  maxTools?: number;
  tokenBudget?: number;
  minScore?: number;
  allowedDomains: string[];
}

const HELP = `mcpalette

Build a small, task-shaped tool palette from an MCP or agent tool catalog.

Usage:
  mcpalette tools.json --task "triage recent GitHub issues"
  cat tools.json | mcpalette --task "summarize release notes" --brief

Options:
  --task <text>              User task used for relevance ranking.
  --max-tools <number>       Maximum selected tools. Default: 8.
  --budget <tokens>          Estimated context token budget. Default: 2400.
  --min-score <number>       Minimum relevance score. Default: 0.25.
  --allowed-domain <domain>  Allow URLs in metadata for this domain. Repeatable.
  --include-risky            Do not exclude high-risk metadata automatically.
  --json                     Print machine-readable result.
  --brief                    Print only the compact agent-facing tool brief.
  --help                     Show this help.
`;

function main(): void {
  try {
    const args = parseArgs(process.argv.slice(2));

    if (!args.task?.trim()) {
      throw new Error("Missing --task. Use --help for examples.");
    }

    const rawInput = readInput(args.file);
    const tools = normalizeTools(JSON.parse(rawInput));
    const paletteOptions: PaletteOptions = {
      includeRisky: args.includeRisky,
      allowedDomains: args.allowedDomains
    };

    if (args.maxTools !== undefined) {
      paletteOptions.maxTools = args.maxTools;
    }
    if (args.tokenBudget !== undefined) {
      paletteOptions.tokenBudget = args.tokenBudget;
    }
    if (args.minScore !== undefined) {
      paletteOptions.minScore = args.minScore;
    }

    const result = createPalette(args.task, tools, paletteOptions);

    if (args.json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      return;
    }

    if (args.brief) {
      process.stdout.write(`${formatToolBrief(result)}\n`);
      return;
    }

    process.stdout.write(`${formatSummary(result)}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`mcpalette: ${message}\n`);
    process.exitCode = 1;
  }
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    json: false,
    brief: false,
    includeRisky: false,
    allowedDomains: []
  };

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (current === undefined) {
      continue;
    }

    if (current === "--help" || current === "-h") {
      process.stdout.write(HELP);
      process.exit(0);
    }

    if (current === "--json") {
      args.json = true;
      continue;
    }

    if (current === "--brief") {
      args.brief = true;
      continue;
    }

    if (current === "--include-risky") {
      args.includeRisky = true;
      continue;
    }

    if (current === "--task") {
      args.task = readOptionValue(argv, index, "--task");
      index += 1;
      continue;
    }

    if (current === "--max-tools") {
      args.maxTools = readNumberOption(argv, index, "--max-tools");
      index += 1;
      continue;
    }

    if (current === "--budget") {
      args.tokenBudget = readNumberOption(argv, index, "--budget");
      index += 1;
      continue;
    }

    if (current === "--min-score") {
      args.minScore = readNumberOption(argv, index, "--min-score");
      index += 1;
      continue;
    }

    if (current === "--allowed-domain") {
      args.allowedDomains.push(readOptionValue(argv, index, "--allowed-domain"));
      index += 1;
      continue;
    }

    if (current.startsWith("-")) {
      throw new Error(`Unknown option: ${current}`);
    }

    if (args.file) {
      throw new Error(`Unexpected extra input path: ${current}`);
    }
    args.file = current;
  }

  return args;
}

function readInput(file: string | undefined): string {
  if (file) {
    return readFileSync(file, "utf8");
  }

  return readFileSync(0, "utf8");
}

function readOptionValue(argv: string[], index: number, option: string): string {
  const value = argv[index + 1];
  if (!value || value.startsWith("-")) {
    throw new Error(`${option} requires a value.`);
  }
  return value;
}

function readNumberOption(argv: string[], index: number, option: string): number {
  const raw = readOptionValue(argv, index, option);
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new Error(`${option} requires a finite number.`);
  }
  return value;
}

function formatSummary(result: PaletteResult): string {
  const lines = [
    `Selected ${result.selected.length} of ${
      result.selected.length + result.rejected.length
    } tools for: ${result.task}`,
    `Budget: ${result.budget.usedTokens}/${result.budget.tokenBudget} estimated tokens`,
    ""
  ];

  if (result.selected.length > 0) {
    lines.push("Selected:");
    for (const entry of result.selected) {
      lines.push(
        `- ${entry.tool.name} score=${entry.score} tokens=${entry.estimatedTokens}`
      );
      if (entry.reasons.length > 0) {
        lines.push(`  ${entry.reasons.slice(0, 3).join("; ")}`);
      }
    }
    lines.push("");
  }

  if (result.rejected.length > 0) {
    const counts = new Map<string, number>();
    for (const entry of result.rejected) {
      counts.set(entry.reason, (counts.get(entry.reason) ?? 0) + 1);
    }
    lines.push(
      `Rejected: ${[...counts.entries()]
        .map(([reason, count]) => `${reason}=${count}`)
        .join(", ")}`
    );
  }

  const importantFindings = result.findings.filter(
    (finding) => finding.severity === "critical" || finding.severity === "high"
  );

  if (importantFindings.length > 0) {
    lines.push("", "High-risk findings:");
    for (const finding of importantFindings.slice(0, 8)) {
      lines.push(
        `- [${finding.severity}] ${finding.tool}.${finding.field}: ${finding.message}`
      );
    }
  }

  return lines.join("\n").trimEnd();
}

main();
