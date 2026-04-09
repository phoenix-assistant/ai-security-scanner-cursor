import type { Rule } from "./types.js";
import { sqlInjectionRule } from "./sql-injection.js";
import { xssRule } from "./xss.js";
import { hardcodedSecretsRule } from "./hardcoded-secrets.js";
import { pathTraversalRule } from "./path-traversal.js";
import { ssrfRule } from "./ssrf.js";

export const builtinRules: Rule[] = [
  sqlInjectionRule,
  xssRule,
  hardcodedSecretsRule,
  pathTraversalRule,
  ssrfRule,
];

export { type Rule, type RuleMatch } from "./types.js";
