import type {
  DriftFinding,
  FindingSeverity,
  RuleId,
  WorkspaceCheckReport,
  WorkspaceSyncReport
} from '../analyzer/workspaceAnalyzer.js';

export const PACKAGE_VERSION = '1.0.0';
export const INFORMATION_URI = 'https://github.com/pie527645-cloud/env-guard-cli';

export type CheckOutputFormat = 'pretty' | 'json' | 'markdown' | 'sarif';
export type SyncOutputFormat = 'pretty' | 'json';

interface SarifRuleDefinition {
  id: RuleId;
  name: string;
  shortDescription: string;
  defaultLevel: 'error' | 'warning' | 'note';
}

const SARIF_RULES: ReadonlyArray<SarifRuleDefinition> = [
  {
    id: 'ENV001',
    name: 'RealSecretInExample',
    shortDescription: 'Real secret or credential detected in .env.example file.',
    defaultLevel: 'error'
  },
  {
    id: 'ENV002',
    name: 'MissingRequiredEnv',
    shortDescription: 'Required environment variable is missing or empty.',
    defaultLevel: 'error'
  },
  {
    id: 'ENV003',
    name: 'WeakSecretValue',
    shortDescription: 'Secret environment variable has a weak, low-entropy, or placeholder value.',
    defaultLevel: 'error'
  },
  {
    id: 'ENV004',
    name: 'SchemaTypeMismatch',
    shortDescription: 'Environment variable fails .env.schema.json type or constraint validation.',
    defaultLevel: 'error'
  },
  {
    id: 'ENV005',
    name: 'EnvParseError',
    shortDescription: 'Syntax error or circular interpolation in environment or schema file.',
    defaultLevel: 'error'
  },
  {
    id: 'ENV006',
    name: 'UndocumentedEnvVar',
    shortDescription: 'Environment variable is used in code or .env without documentation in .env.example.',
    defaultLevel: 'warning'
  },
  {
    id: 'ENV007',
    name: 'UnusedEnvVar',
    shortDescription: 'Environment variable is defined in .env or .env.example but unreferenced in code.',
    defaultLevel: 'note'
  }
];

function severityToSarifLevel(severity: FindingSeverity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
  }
}

export function formatSarifReport(report: WorkspaceCheckReport): string {
  const ruleIndexMap = new Map<RuleId, number>();
  SARIF_RULES.forEach((r, idx) => ruleIndexMap.set(r.id, idx));

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'env-guard',
            version: PACKAGE_VERSION,
            informationUri: INFORMATION_URI,
            rules: SARIF_RULES.map((r) => ({
              id: r.id,
              name: r.name,
              shortDescription: { text: r.shortDescription },
              defaultConfiguration: { level: r.defaultLevel }
            }))
          }
        },
        results: report.findings.map((f: DriftFinding) => ({
          ruleId: f.ruleId,
          ruleIndex: ruleIndexMap.get(f.ruleId) ?? 0,
          level: severityToSarifLevel(f.severity),
          message: {
            text: f.message
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: f.file,
                  uriBaseId: '%SRCROOT%'
                },
                region: {
                  startLine: Math.max(1, f.line)
                }
              }
            }
          ],
          properties: {
            severity: f.severity,
            key: f.key,
            redactedValue: f.redactedValue
          }
        }))
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

export function formatCheckReport(
  report: WorkspaceCheckReport,
  format: CheckOutputFormat
): string {
  if (format === 'sarif') {
    return formatSarifReport(report);
  }

  if (format === 'json') {
    return JSON.stringify(
      {
        summary: {
          scannedFilesCount: report.scannedFilesCount,
          totalKeys: report.keys.length,
          findingsCount: report.findings.length,
          missingCount: report.missingKeys.length,
          undocumentedCount: report.undocumentedKeys.length,
          unusedCount: report.unusedKeys.length
        },
        missingKeys: report.missingKeys,
        undocumentedKeys: report.undocumentedKeys,
        unusedKeys: report.unusedKeys,
        findings: report.findings,
        keys: report.keys
      },
      null,
      2
    );
  }

  if (format === 'markdown') {
    const lines: string[] = [
      '# env-guard Check Report',
      '',
      `- **Scanned Code Files:** ${report.scannedFilesCount}`,
      `- **Discovered Keys:** ${report.keys.length}`,
      `- **Total Findings:** ${report.findings.length}`,
      ''
    ];
    if (report.findings.length === 0) {
      lines.push('No drift or secret hygiene issues found.');
    } else {
      lines.push('| Severity | Rule | Key | Location | Redacted | Details |');
      lines.push('| --- | --- | --- | --- | --- | --- |');
      for (let i = 0; i < report.findings.length; i++) {
        const f = report.findings[i]!;
        const safeMsg = f.message.replaceAll('|', '\\|');
        lines.push(
          `| ${f.severity.toUpperCase()} | ${f.ruleId} | \`${f.key}\` | \`${f.file}:${f.line}\` | \`${f.redactedValue}\` | ${safeMsg} |`
        );
      }
    }
    return lines.join('\n');
  }

  // pretty format
  const lines: string[] = [
    `env-guard check (${report.keys.length} keys across ${report.scannedFilesCount} scanned files)`
  ];
  if (report.findings.length === 0) {
    lines.push('PASS: 0 drift or secret hygiene findings.');
    return lines.join('\n');
  }

  lines.push(`Found ${report.findings.length} finding(s):`);
  for (let i = 0; i < report.findings.length; i++) {
    const f = report.findings[i]!;
    lines.push(
      `  [${f.severity.toUpperCase()}] ${f.ruleId} (${f.key} = ${f.redactedValue}) at ${f.file}:${f.line} - ${f.message}`
    );
  }
  return lines.join('\n');
}

export function formatSyncReport(
  report: WorkspaceSyncReport,
  format: SyncOutputFormat
): string {
  if (format === 'json') {
    return JSON.stringify(
      {
        allKeys: report.allKeys,
        inCode: report.inCode,
        inEnv: report.inEnv,
        inExample: report.inExample,
        inSchema: report.inSchema,
        missingInExample: report.missingInExample,
        missingInEnv: report.missingInEnv,
        unusedInCode: report.unusedInCode,
        scrubbedSecretsInExampleCount: report.scrubbedSecretsInExampleCount,
        writtenExample: report.writtenExamplePath !== null
      },
      null,
      2
    );
  }

  const lines: string[] = [
    `env-guard sync summary:`,
    `  Total keys discovered : ${report.allKeys.length}`,
    `  Referenced in code    : ${report.inCode.length}`,
    `  Defined in .env       : ${report.inEnv.length}`,
    `  Documented in example : ${report.inExample.length}`,
    `  Defined in schema     : ${report.inSchema.length}`,
    `  Missing in example    : ${report.missingInExample.length}${report.missingInExample.length > 0 ? ` (${report.missingInExample.join(', ')})` : ''}`,
    `  Missing in .env       : ${report.missingInEnv.length}${report.missingInEnv.length > 0 ? ` (${report.missingInEnv.join(', ')})` : ''}`,
    `  Unused in code        : ${report.unusedInCode.length}${report.unusedInCode.length > 0 ? ` (${report.unusedInCode.join(', ')})` : ''}`
  ];
  if (report.writtenExamplePath !== null) {
    lines.push(`  Wrote scrubbed .env.example (${report.allKeys.length} keys, 0 real values copied).`);
  }
  return lines.join('\n');
}
