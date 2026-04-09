import type { Finding } from "./findings.js";

export interface LLMConfig {
  apiKey: string;
  baseUrl?: string;
  model?: string;
  maxTokens?: number;
}

interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

interface ChatResponse {
  choices: Array<{
    message: { content: string };
  }>;
}

export class LLMClient {
  private readonly config: LLMConfig;

  constructor(config: LLMConfig) {
    this.config = {
      baseUrl: "https://api.openai.com/v1",
      model: "gpt-4o-mini",
      maxTokens: 1024,
      ...config,
    };
  }

  async explain(finding: Finding): Promise<string> {
    const prompt = `You are a security expert. Explain this vulnerability to a developer.

**Vulnerability:** ${finding.title} (${finding.severity})
**File:** ${finding.file}:${finding.line}
**Code:**
\`\`\`
${finding.snippet}
\`\`\`
**Description:** ${finding.description}

Explain:
1. Why this code is vulnerable
2. How an attacker could exploit it
3. Real-world impact

Be concise. Use plain English. Max 200 words.`;

    return this.chat([
      { role: "system", content: "You are a senior application security engineer." },
      { role: "user", content: prompt },
    ]);
  }

  async suggestFix(finding: Finding): Promise<string> {
    const prompt = `You are a security expert. Suggest a fix for this vulnerability.

**Vulnerability:** ${finding.title} (${finding.severity})
**Language:** ${finding.language}
**Code:**
\`\`\`
${finding.snippet}
\`\`\`
**Description:** ${finding.description}

Provide the fixed code with a brief explanation. Use idiomatic patterns for the language. Only output the fix — no preamble.`;

    return this.chat([
      { role: "system", content: "You are a senior application security engineer." },
      { role: "user", content: prompt },
    ]);
  }

  private async chat(messages: ChatMessage[]): Promise<string> {
    const response = await fetch(`${this.config.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify({
        model: this.config.model,
        messages,
        max_tokens: this.config.maxTokens,
        temperature: 0.3,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`LLM request failed (${response.status}): ${error}`);
    }

    const data = (await response.json()) as ChatResponse;
    return data.choices[0]?.message.content ?? "";
  }
}
