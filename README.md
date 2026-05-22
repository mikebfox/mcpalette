# mcpalette

`mcpalette` builds a small, task-shaped palette from a larger MCP or agent tool catalog.

Agent runtimes are getting more tools, more autonomy, and more risk surface. Exposing every available tool to every task increases context cost and makes tool metadata a supply-chain input. `mcpalette` keeps that boundary boring: deterministic ranking, context budgeting, and metadata audit in one zero-runtime-dependency TypeScript package.

## What it does

- Ranks tools against a user task using local lexical matching.
- Selects the smallest useful set under `maxTools` and an estimated token budget.
- Rejects high-risk tool metadata by default.
- Flags hidden Unicode, prompt-override wording, secret exfiltration hints, risky shell snippets, oversized metadata, and URLs outside an allowlist.
- Emits either structured JSON or a compact agent-facing brief.

## Install

`mcpalette` is not published to the npm registry yet. Install it from GitHub:

```sh
npm install -D github:mikebfox/mcpalette
```

Requires Node.js 20 or newer.

## Library usage

```ts
import { createPalette, formatToolBrief } from "mcpalette";

const tools = [
  {
    name: "github.searchIssues",
    description: "Search GitHub issues by repository, label, assignee, and update time.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string" }
      }
    }
  },
  {
    name: "calendar.createEvent",
    description: "Create a calendar event with guests and a start time."
  }
];

const palette = createPalette("find recent GitHub issues", tools, {
  maxTools: 4,
  tokenBudget: 1200,
  allowedDomains: ["github.com"]
});

console.log(palette.selected.map((entry) => entry.tool.name));
console.log(formatToolBrief(palette));
```

## CLI usage

```sh
npm exec mcpalette -- tools.json --task "find recent GitHub issues" --max-tools 4 --budget 1200
```

Use stdin when you do not want a file path:

```sh
cat tools.json | npm exec mcpalette -- --task "summarize release notes" --brief
```

Machine-readable output:

```sh
npm exec mcpalette -- tools.json --task "triage a repository" --json
```

## Input shape

`mcpalette` accepts an array of tools:

```json
[
  {
    "name": "docs.search",
    "description": "Search internal docs.",
    "inputSchema": {
      "type": "object",
      "properties": {
        "query": { "type": "string" }
      }
    }
  }
]
```

It also accepts common MCP `listTools` wrappers:

```json
{
  "result": {
    "tools": [
      {
        "name": "docs.search",
        "description": "Search internal docs."
      }
    ]
  }
}
```

## API

### `createPalette(task, tools, options)`

Returns selected and rejected tools with scores, findings, reasons, and budget usage.

Key options:

- `maxTools`: maximum selected tools. Default: `8`.
- `tokenBudget`: estimated context budget. Default: `2400`.
- `minScore`: minimum relevance score. Default: `0.25` for non-empty tasks.
- `includeRisky`: include high-risk metadata instead of rejecting it. Default: `false`.
- `allowedDomains`: URL host allowlist for tool metadata.
- `aliases`: task-token expansions, useful for local vocabulary.

### `auditTool(tool, options)`

Runs metadata checks without selecting tools.

### `formatToolBrief(result, options)`

Builds a compact text block for agent context. Suspicious Unicode is stripped from the brief.

## Design notes

`mcpalette` is intentionally small. It is not a full policy engine, an MCP proxy, or an LLM-based security classifier. Put it before those layers when you need a fast local pre-filter: choose fewer tools, spend fewer tokens, and review suspicious metadata before it becomes agent context.

## Development

```sh
npm install
npm test
```

## License

MIT
