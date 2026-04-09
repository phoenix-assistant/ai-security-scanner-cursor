import * as vscode from "vscode";
import { Scanner } from "@ai-security-scanner/core";
import type { Finding } from "@ai-security-scanner/core";

const DIAGNOSTIC_SOURCE = "AI Security Scanner";
const scanner = new Scanner();

let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection = vscode.languages.createDiagnosticCollection("aiSecurityScanner");
  context.subscriptions.push(diagnosticCollection);

  // Scan on file open
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document);
  }

  // Scan on file change/open
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) scanDocument(editor.document);
    })
  );

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration("aiSecurityScanner");
      if (config.get<boolean>("enableOnSave", true)) {
        scanDocument(document);
      }
    })
  );

  // Scan on type (debounced)
  let typeTimer: ReturnType<typeof setTimeout> | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const config = vscode.workspace.getConfiguration("aiSecurityScanner");
      if (!config.get<boolean>("enableOnType", false)) return;

      if (typeTimer) clearTimeout(typeTimer);
      typeTimer = setTimeout(() => scanDocument(event.document), 500);
    })
  );

  // Manual scan command
  context.subscriptions.push(
    vscode.commands.registerCommand("aiSecurityScanner.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        scanDocument(editor.document);
        vscode.window.showInformationMessage("Security scan complete.");
      }
    })
  );

  // Scan workspace command
  context.subscriptions.push(
    vscode.commands.registerCommand("aiSecurityScanner.scanWorkspace", async () => {
      const files = await vscode.workspace.findFiles(
        "**/*.{js,jsx,ts,tsx,py,rb,go,java,rs,html,vue,svelte}",
        "**/node_modules/**"
      );

      let totalFindings = 0;
      for (const uri of files) {
        const document = await vscode.workspace.openTextDocument(uri);
        totalFindings += scanDocument(document);
      }

      vscode.window.showInformationMessage(
        `Workspace scan complete. ${totalFindings} finding(s) in ${files.length} files.`
      );
    })
  );
}

function scanDocument(document: vscode.TextDocument): number {
  const language = Scanner.inferLanguage(document.fileName);
  const content = document.getText();
  const result = scanner.scan(content, language, { file: document.fileName });

  const diagnostics = result.findings.map(findingToDiagnostic);
  diagnosticCollection.set(document.uri, diagnostics);

  return result.findings.length;
}

function findingToDiagnostic(finding: Finding): vscode.Diagnostic {
  const line = Math.max(0, finding.line - 1);
  const range = new vscode.Range(line, 0, finding.endLine ? finding.endLine - 1 : line, 999);

  const severity = mapSeverity(finding.severity);
  const diagnostic = new vscode.Diagnostic(range, `${finding.title}: ${finding.description}`, severity);
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = finding.ruleId;
  return diagnostic;
}

function mapSeverity(severity: Finding["severity"]): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    case "info":
      return vscode.DiagnosticSeverity.Hint;
  }
}

export function deactivate(): void {
  diagnosticCollection?.dispose();
}
