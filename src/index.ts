export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type FindingCode =
  | "hidden-unicode"
  | "prompt-override"
  | "secret-exfiltration"
  | "shell-execution"
  | "unapproved-domain"
  | "oversized-metadata";

export type RejectionReason = "risky" | "below-score" | "budget" | "max-tools";

export interface ToolDefinition {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: Record<string, unknown>;
  source?: string;
  [key: string]: unknown;
}

export interface AuditOptions {
  allowedDomains?: readonly string[];
  maxDescriptionTokens?: number;
}

export interface PaletteOptions extends AuditOptions {
  maxTools?: number;
  minScore?: number;
  tokenBudget?: number;
  includeRisky?: boolean;
  riskPenalty?: number;
  aliases?: Record<string, readonly string[]>;
}

export interface AuditFinding {
  tool: string;
  field: string;
  code: FindingCode;
  severity: Severity;
  message: string;
  snippet?: string;
  offset?: number;
}

export interface RankedTool {
  tool: ToolDefinition;
  score: number;
  rawScore: number;
  riskScore: number;
  estimatedTokens: number;
  findings: AuditFinding[];
  reasons: string[];
}

export interface RejectedTool extends RankedTool {
  reason: RejectionReason;
}

export interface PaletteResult {
  task: string;
  selected: RankedTool[];
  rejected: RejectedTool[];
  findings: AuditFinding[];
  budget: {
    maxTools: number;
    tokenBudget: number;
    usedTokens: number;
    remainingTokens: number;
  };
}

export interface BriefOptions {
  includeSchemas?: boolean;
  maxDescriptionChars?: number;
}

interface TextField {
  field: string;
  value: string;
}

interface PatternRule {
  code: FindingCode;
  severity: Severity;
  message: string;
  pattern: RegExp;
}

const DEFAULT_MAX_TOOLS = 8;
const DEFAULT_TOKEN_BUDGET = 2400;
const DEFAULT_MIN_SCORE = 0.25;
const DEFAULT_RISK_PENALTY = 0.75;
const DEFAULT_MAX_DESCRIPTION_TOKENS = 420;

const STOP_WORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "by",
  "for",
  "from",
  "how",
  "in",
  "into",
  "is",
  "it",
  "of",
  "on",
  "or",
  "that",
  "the",
  "this",
  "to",
  "use",
  "using",
  "with"
]);

const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 3,
  high: 7,
  critical: 12
};

const INSTRUCTION_RULES: readonly PatternRule[] = [
  {
    code: "prompt-override",
    severity: "high",
    message: "Looks like an instruction to override higher-priority agent rules.",
    pattern: /\b(ignore|forget|bypass|override)\b.{0,48}\b(previous|prior|above|system|developer|safety|policy|instructions?)\b/iu
  },
  {
    code: "prompt-override",
    severity: "high",
    message: "Mentions hidden or system-level prompt control inside tool metadata.",
    pattern: /\b(system prompt|developer message|hidden instructions?|do not (tell|reveal|mention)|secret instructions?)\b/iu
  },
  {
    code: "secret-exfiltration",
    severity: "critical",
    message: "Looks like an attempt to read or transmit secrets.",
    pattern: /\b(read|print|send|upload|post|exfiltrat\w*|steal|leak)\b.{0,64}\b(\.env|api[_-]?key|token|secret|credential|password|ssh|private key)\b/iu
  },
  {
    code: "secret-exfiltration",
    severity: "high",
    message: "Mentions credentials in a way that deserves review before exposure to an agent.",
    pattern: /\b(github|openai|anthropic|aws|gcp|azure|slack|npm)\b.{0,32}\b(token|key|secret|credential)\b/iu
  },
  {
    code: "shell-execution",
    severity: "high",
    message: "Contains a risky shell execution pattern.",
    pattern: /\b((curl|wget)\b[^|;\n]{0,120}\|\s*(sh|bash)|eval\s*\(|rm\s+-rf|chmod\s+\+x|base64\s+(-d|--decode)|powershell\s+-enc)\b/iu
  }
];

export function createPalette(
  task: string,
  tools: readonly ToolDefinition[],
  options: PaletteOptions = {}
): PaletteResult {
  const maxTools = positiveInteger(options.maxTools, DEFAULT_MAX_TOOLS);
  const tokenBudget = positiveInteger(options.tokenBudget, DEFAULT_TOKEN_BUDGET);
  const minScore = finiteNumber(
    options.minScore,
    task.trim() ? DEFAULT_MIN_SCORE : 0
  );

  const ranked = rankTools(task, tools, options);
  const selected: RankedTool[] = [];
  const rejected: RejectedTool[] = [];
  let usedTokens = 0;

  for (const entry of ranked) {
    const hasHighRisk = entry.findings.some(
      (finding) => finding.severity === "high" || finding.severity === "critical"
    );

    if (!options.includeRisky && hasHighRisk) {
      rejected.push({ ...entry, reason: "risky" });
      continue;
    }

    if (entry.score < minScore) {
      rejected.push({ ...entry, reason: "below-score" });
      continue;
    }

    if (selected.length >= maxTools) {
      rejected.push({ ...entry, reason: "max-tools" });
      continue;
    }

    if (usedTokens + entry.estimatedTokens > tokenBudget) {
      rejected.push({ ...entry, reason: "budget" });
      continue;
    }

    selected.push(entry);
    usedTokens += entry.estimatedTokens;
  }

  return {
    task,
    selected,
    rejected,
    findings: ranked.flatMap((entry) => entry.findings),
    budget: {
      maxTools,
      tokenBudget,
      usedTokens,
      remainingTokens: Math.max(0, tokenBudget - usedTokens)
    }
  };
}

export function rankTools(
  task: string,
  tools: readonly ToolDefinition[],
  options: PaletteOptions = {}
): RankedTool[] {
  return tools
    .map((tool) => rankTool(task, tool, options))
    .sort(compareRankedTools);
}

export function rankTool(
  task: string,
  tool: ToolDefinition,
  options: PaletteOptions = {}
): RankedTool {
  const fields = collectTextFields(tool);
  const findings = auditTool(tool, options);
  const taskTokens = expandAliases(tokenize(task), options.aliases);
  const nameText = textForField(fields, "name");
  const descriptionText = textForField(fields, "description");
  const schemaText = textForField(fields, "inputSchema");
  const nameTokens = new Set(tokenize(nameText));
  const descriptionTokens = new Set(tokenize(descriptionText));
  const schemaTokens = new Set(tokenize(schemaText));
  const reasons = new Set<string>();
  let rawScore = 0;

  for (const token of taskTokens) {
    if (nameTokens.has(token)) {
      rawScore += 4;
      reasons.add(`name matches "${token}"`);
      continue;
    }

    if (descriptionTokens.has(token)) {
      rawScore += 1.5;
      reasons.add(`description matches "${token}"`);
      continue;
    }

    if (schemaTokens.has(token)) {
      rawScore += 0.6;
      reasons.add(`schema matches "${token}"`);
      continue;
    }

    const fuzzyScore = fuzzyTokenScore(token, nameTokens, descriptionTokens);
    if (fuzzyScore > 0) {
      rawScore += fuzzyScore;
      reasons.add(`near match for "${token}"`);
    }
  }

  if (descriptionText.trim()) {
    rawScore += 0.2;
  } else {
    rawScore -= 0.4;
    reasons.add("missing description");
  }

  const riskScore = findings.reduce(
    (sum, finding) => sum + SEVERITY_WEIGHT[finding.severity],
    0
  );
  const riskPenalty = finiteNumber(options.riskPenalty, DEFAULT_RISK_PENALTY);
  const score = Math.max(0, round(rawScore - riskScore * riskPenalty));

  return {
    tool,
    score,
    rawScore: round(rawScore),
    riskScore,
    estimatedTokens: estimateToolTokens(tool),
    findings,
    reasons: [...reasons]
  };
}

export function auditTools(
  tools: readonly ToolDefinition[],
  options: AuditOptions = {}
): AuditFinding[] {
  return tools.flatMap((tool) => auditTool(tool, options));
}

export function auditTool(
  tool: ToolDefinition,
  options: AuditOptions = {}
): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const maxDescriptionTokens = positiveInteger(
    options.maxDescriptionTokens,
    DEFAULT_MAX_DESCRIPTION_TOKENS
  );

  for (const field of collectTextFields(tool)) {
    findings.push(...findHiddenUnicode(tool.name, field));
    findings.push(...findInstructionPatterns(tool.name, field));
    findings.push(...findUnapprovedDomains(tool.name, field, options.allowedDomains));

    if (
      (field.field === "description" || field.field === "inputSchema") &&
      estimateTokens(field.value) > maxDescriptionTokens
    ) {
      findings.push(
        makeFinding({
          tool: tool.name,
          field: field.field,
          code: "oversized-metadata",
          severity: "low",
          message: `Metadata is larger than ${maxDescriptionTokens} estimated tokens.`,
          snippet: compact(stripSuspiciousUnicode(field.value), 160)
        })
      );
    }
  }

  return findings.sort(compareFindings);
}

export function normalizeTools(input: unknown): ToolDefinition[] {
  const list = extractToolList(input);
  return list.map((item, index) => normalizeTool(item, index));
}

export function estimateTokens(value: unknown): number {
  const text = typeof value === "string" ? value : stableStringify(value);
  return Math.max(1, Math.ceil(text.length / 4));
}

export function estimateToolTokens(tool: ToolDefinition): number {
  return estimateTokens({
    name: tool.name,
    description: tool.description ?? "",
    inputSchema: tool.inputSchema ?? null
  });
}

export function stripSuspiciousUnicode(text: string): string {
  let stripped = "";
  for (const char of text) {
    const codePoint = char.codePointAt(0);
    if (codePoint === undefined || classifySuspiciousCodePoint(codePoint)) {
      continue;
    }
    stripped += char;
  }
  return stripped;
}

export function formatToolBrief(
  result: PaletteResult,
  options: BriefOptions = {}
): string {
  const maxDescriptionChars = positiveInteger(options.maxDescriptionChars, 220);
  const lines = [
    `Tool palette for: ${result.task || "unspecified task"}`,
    `Selected ${result.selected.length} of ${
      result.selected.length + result.rejected.length
    } tools, ${result.budget.usedTokens}/${result.budget.tokenBudget} estimated tokens.`
  ];

  for (const entry of result.selected) {
    const description = compact(
      stripSuspiciousUnicode(entry.tool.description ?? "No description."),
      maxDescriptionChars
    );
    lines.push(`- ${entry.tool.name}: ${description}`);

    if (options.includeSchemas && entry.tool.inputSchema !== undefined) {
      lines.push(`  inputSchema: ${compact(stableStringify(entry.tool.inputSchema), 420)}`);
    }
  }

  const selectedFindings = result.selected.flatMap((entry) => entry.findings);
  if (selectedFindings.length > 0) {
    lines.push("Metadata notes:");
    for (const finding of selectedFindings.slice(0, 8)) {
      lines.push(
        `- [${finding.severity}] ${finding.tool}.${finding.field}: ${finding.message}`
      );
    }
  }

  return lines.join("\n");
}

function collectTextFields(tool: ToolDefinition): TextField[] {
  const fields: TextField[] = [{ field: "name", value: tool.name }];

  if (typeof tool.description === "string") {
    fields.push({ field: "description", value: tool.description });
  }

  if (tool.inputSchema !== undefined) {
    fields.push({ field: "inputSchema", value: stableStringify(tool.inputSchema) });
  }

  if (tool.annotations !== undefined) {
    fields.push({ field: "annotations", value: stableStringify(tool.annotations) });
  }

  return fields;
}

function findHiddenUnicode(toolName: string, field: TextField): AuditFinding[] {
  const groups = new Map<
    string,
    { severity: Severity; label: string; codePoints: string[]; offset: number }
  >();
  let offset = 0;

  for (const char of field.value) {
    const codePoint = char.codePointAt(0);
    if (codePoint === undefined) {
      offset += char.length;
      continue;
    }

    const classification = classifySuspiciousCodePoint(codePoint);
    if (!classification) {
      offset += char.length;
      continue;
    }

    const key = classification.label;
    const existing = groups.get(key);
    const codePointLabel = toCodePointLabel(codePoint);

    if (existing) {
      if (!existing.codePoints.includes(codePointLabel) && existing.codePoints.length < 5) {
        existing.codePoints.push(codePointLabel);
      }
    } else {
      groups.set(key, {
        severity: classification.severity,
        label: classification.label,
        codePoints: [codePointLabel],
        offset
      });
    }

    offset += char.length;
  }

  return [...groups.values()].map((group) =>
    makeFinding({
      tool: toolName,
      field: field.field,
      code: "hidden-unicode",
      severity: group.severity,
      message: `${group.label} detected: ${group.codePoints.join(", ")}.`,
      snippet: compact(stripSuspiciousUnicode(field.value), 160),
      offset: group.offset
    })
  );
}

function classifySuspiciousCodePoint(
  codePoint: number
): { severity: Severity; label: string } | undefined {
  if (
    (codePoint >= 0x202a && codePoint <= 0x202e) ||
    (codePoint >= 0x2066 && codePoint <= 0x2069)
  ) {
    return { severity: "high", label: "Bidirectional text control" };
  }

  if (
    (codePoint >= 0xe0000 && codePoint <= 0xe007f) ||
    (codePoint >= 0xe0100 && codePoint <= 0xe01ef)
  ) {
    return { severity: "high", label: "Invisible tag or variation payload" };
  }

  if (
    (codePoint >= 0x200b && codePoint <= 0x200f) ||
    codePoint === 0x2060 ||
    codePoint === 0xfeff
  ) {
    return { severity: "medium", label: "Zero-width formatting character" };
  }

  if (codePoint >= 0xfe00 && codePoint <= 0xfe0f) {
    return { severity: "medium", label: "Variation selector" };
  }

  if ((codePoint >= 0x00 && codePoint <= 0x08) || codePoint === 0x0b || codePoint === 0x0c) {
    return { severity: "high", label: "Non-printable control character" };
  }

  if ((codePoint >= 0x0e && codePoint <= 0x1f) || codePoint === 0x7f) {
    return { severity: "medium", label: "Non-printable control character" };
  }

  if (codePoint === 0x3000) {
    return { severity: "low", label: "Ideographic space" };
  }

  return undefined;
}

function findInstructionPatterns(toolName: string, field: TextField): AuditFinding[] {
  const findings: AuditFinding[] = [];

  for (const rule of INSTRUCTION_RULES) {
    const match = rule.pattern.exec(field.value);
    if (!match) {
      continue;
    }

    findings.push(
      makeFinding({
        tool: toolName,
        field: field.field,
        code: rule.code,
        severity: rule.severity,
        message: rule.message,
        snippet: compact(stripSuspiciousUnicode(match[0]), 160),
        offset: match.index
      })
    );
  }

  return findings;
}

function findUnapprovedDomains(
  toolName: string,
  field: TextField,
  allowedDomains: readonly string[] | undefined
): AuditFinding[] {
  if (!allowedDomains || allowedDomains.length === 0) {
    return [];
  }

  const findings: AuditFinding[] = [];
  const allowed = allowedDomains.map(normalizeDomain).filter(Boolean);
  const urlPattern = /\bhttps?:\/\/[^\s<>"')]+/giu;
  let match: RegExpExecArray | null;

  while ((match = urlPattern.exec(field.value)) !== null) {
    const rawUrl = match[0];
    let hostname: string;
    try {
      hostname = normalizeDomain(new URL(rawUrl).hostname);
    } catch {
      continue;
    }

    if (!allowed.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) {
      findings.push(
        makeFinding({
          tool: toolName,
          field: field.field,
          code: "unapproved-domain",
          severity: "low",
          message: `URL points to "${hostname}", which is outside the allowed domain list.`,
          snippet: rawUrl,
          offset: match.index
        })
      );
    }
  }

  return findings;
}

function compareRankedTools(left: RankedTool, right: RankedTool): number {
  return (
    right.score - left.score ||
    left.riskScore - right.riskScore ||
    left.estimatedTokens - right.estimatedTokens ||
    left.tool.name.localeCompare(right.tool.name)
  );
}

function compareFindings(left: AuditFinding, right: AuditFinding): number {
  return (
    SEVERITY_WEIGHT[right.severity] - SEVERITY_WEIGHT[left.severity] ||
    left.tool.localeCompare(right.tool) ||
    left.field.localeCompare(right.field) ||
    left.code.localeCompare(right.code)
  );
}

function textForField(fields: readonly TextField[], name: string): string {
  return fields.find((field) => field.field === name)?.value ?? "";
}

function tokenize(text: string): string[] {
  return [
    ...new Set(
      normalizeForSearch(text)
        .split(/[^\p{L}\p{N}_./:-]+/u)
        .map(stemToken)
        .filter((token) => token.length > 1 && !STOP_WORDS.has(token))
    )
  ];
}

function expandAliases(
  tokens: string[],
  aliases: Record<string, readonly string[]> | undefined
): string[] {
  if (!aliases) {
    return tokens;
  }

  const expanded = new Set(tokens);
  for (const token of tokens) {
    for (const alias of aliases[token] ?? []) {
      for (const aliasToken of tokenize(alias)) {
        expanded.add(aliasToken);
      }
    }
  }

  return [...expanded];
}

function fuzzyTokenScore(
  token: string,
  nameTokens: ReadonlySet<string>,
  descriptionTokens: ReadonlySet<string>
): number {
  for (const candidate of nameTokens) {
    if (isNearToken(token, candidate)) {
      return 1.2;
    }
  }

  for (const candidate of descriptionTokens) {
    if (isNearToken(token, candidate)) {
      return 0.4;
    }
  }

  return 0;
}

function isNearToken(token: string, candidate: string): boolean {
  return (
    token.length >= 4 &&
    candidate.length >= 4 &&
    (candidate.startsWith(token) || token.startsWith(candidate))
  );
}

function stemToken(token: string): string {
  if (!/^[a-z0-9_-]+$/u.test(token)) {
    return token;
  }

  return token
    .replace(/(?:ing|edly|edly|ed|es|s)$/u, "")
    .replace(/[_-]+/gu, "-");
}

function normalizeForSearch(text: string): string {
  return stripSuspiciousUnicode(text)
    .normalize("NFKC")
    .toLocaleLowerCase("en-US");
}

function extractToolList(input: unknown): unknown[] {
  if (Array.isArray(input)) {
    return input;
  }

  const record = asRecord(input);
  if (!record) {
    throw new TypeError("Expected an array of tools or an object containing a tools array.");
  }

  if (Array.isArray(record["tools"])) {
    return record["tools"];
  }

  const result = asRecord(record["result"]);
  if (result && Array.isArray(result["tools"])) {
    return result["tools"];
  }

  throw new TypeError("Expected an array of tools or an object containing a tools array.");
}

function normalizeTool(item: unknown, index: number): ToolDefinition {
  if (typeof item === "string" && item.trim()) {
    return { name: item.trim() };
  }

  const record = asRecord(item);
  if (!record) {
    throw new TypeError(`Tool at index ${index} must be an object or non-empty string.`);
  }

  const name =
    stringValue(record["name"]) ??
    stringValue(record["id"]) ??
    stringValue(record["tool"]) ??
    stringValue(record["title"]);

  if (!name) {
    throw new TypeError(`Tool at index ${index} is missing a name.`);
  }

  const tool: ToolDefinition = { name };
  const description = stringValue(record["description"]);
  const source = stringValue(record["source"]);
  const annotations = asRecord(record["annotations"]);

  if (description) {
    tool.description = description;
  }

  if (source) {
    tool.source = source;
  }

  if (annotations) {
    tool.annotations = annotations;
  }

  if ("inputSchema" in record) {
    tool.inputSchema = record["inputSchema"];
  } else if ("schema" in record) {
    tool.inputSchema = record["schema"];
  } else if ("parameters" in record) {
    tool.inputSchema = record["parameters"];
  }

  return tool;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function stableStringify(value: unknown): string {
  const seen = new WeakSet<object>();
  return JSON.stringify(
    value,
    (_key, nestedValue: unknown) => {
      if (nestedValue === null || typeof nestedValue !== "object") {
        return nestedValue;
      }

      if (seen.has(nestedValue)) {
        return "[Circular]";
      }
      seen.add(nestedValue);

      if (Array.isArray(nestedValue)) {
        return nestedValue;
      }

      return Object.fromEntries(
        Object.entries(nestedValue as Record<string, unknown>).sort(([left], [right]) =>
          left.localeCompare(right)
        )
      );
    },
    0
  );
}

function compact(text: string, maxLength: number): string {
  const normalized = text.replace(/\s+/gu, " ").trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }

  return `${normalized.slice(0, Math.max(0, maxLength - 1)).trim()}...`;
}

function makeFinding(input: {
  tool: string;
  field: string;
  code: FindingCode;
  severity: Severity;
  message: string;
  snippet?: string;
  offset?: number;
}): AuditFinding {
  const finding: AuditFinding = {
    tool: input.tool,
    field: input.field,
    code: input.code,
    severity: input.severity,
    message: input.message
  };

  if (input.snippet !== undefined) {
    finding.snippet = input.snippet;
  }

  if (input.offset !== undefined) {
    finding.offset = input.offset;
  }

  return finding;
}

function toCodePointLabel(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

function normalizeDomain(domain: string): string {
  return domain.trim().replace(/\.$/u, "").toLocaleLowerCase("en-US");
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && value !== undefined && value > 0
    ? Math.floor(value)
    : fallback;
}

function finiteNumber(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && value !== undefined ? value : fallback;
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}
