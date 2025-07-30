import type { Guard, GuardOptions } from '@hai-guardrails/types'
import { makeGuard } from '@hai-guardrails/guards'

type PIIRegex = {
	id: string
	name: string
	description: string
	regex: RegExp
	replacement: string
}

const PII_REGEX_REGISTRY = [
	{
		id: 'email',
		name: 'Email',
		description: 'Email addresses',
		regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
		replacement: '[REDACTED-EMAIL]',
	},
	{
		id: 'phone',
		name: 'Phone',
		description: 'Phone numbers',
		regex: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g,
		replacement: '[REDACTED-PHONE]',
	},
	{
		id: 'ssn',
		name: 'SSN',
		description: 'Social Security Numbers',
		regex: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g,
		replacement: '[REDACTED-SSN]',
	},
	{
		id: 'credit-card',
		name: 'Credit Card',
		description: 'Credit Card Numbers',
		regex: /\b\d{4}[-.]?\d{4}[-.]?\d{4}[-.]?\d{4}\b/g,
		replacement: '[REDACTED-CREDIT-CARD]',
	},
	{
		id: 'ip-address',
		name: 'IP Address',
		description: 'IP Addresses',
		regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
		replacement: '[REDACTED-IP-ADDRESS]',
	},
	// Healthcare Identifiers
	{
		id: 'icd10',
		name: 'ICD-10 Code',
		description: 'ICD-10 medical diagnosis codes',
		regex: /\b[A-TV-Z][0-9]{2}(\.[0-9A-TV-Z]{1,4})?\b/g,
		replacement: '[REDACTED-ICD10]',
	},
	{
		id: 'mrn-numeric',
		name: 'Medical Record Number',
		description: 'Numeric medical record numbers (7-10 digits)',
		regex: /\b(MRN?[-:]?\s*)?[0-9]{7,10}\b/gi,
		replacement: '[REDACTED-MRN]',
	},
	{
		id: 'mrn-alphanumeric',
		name: 'Medical Record Number',
		description: 'Alphanumeric medical record numbers with prefix',
		regex: /\b(MR|MRN|MEDICAL\s*RECORD)[-:\s]*[A-Z0-9]{6,12}\b/gi,
		replacement: '[REDACTED-MRN]',
	},
	{
		id: 'npi',
		name: 'NPI Number',
		description: 'National Provider Identifier (10 digits)',
		regex: /\bNPI[-:\s]*[0-9]{10}\b/gi,
		replacement: '[REDACTED-NPI]',
	},
	{
		id: 'dea',
		name: 'DEA Number',
		description: 'Drug Enforcement Administration numbers',
		regex: /\bDEA[-:\s]*[A-Z]{2}[0-9]{7}\b/gi,
		replacement: '[REDACTED-DEA]',
	},
	// Additional Healthcare Identifiers
	{
		id: 'hicn',
		name: 'HICN',
		description: 'Health Insurance Claim Numbers (Medicare)',
		regex: /\b\d{3}[-.]?\d{2}[-.]?\d{4}[A-Z]\b/g,
		replacement: '[REDACTED-HICN]',
	},
	{
		id: 'patient-id',
		name: 'Patient ID',
		description: 'Patient identifiers with various prefixes',
		regex: /\b(PID|PATID|PAT)[-:]?\s*[A-Z0-9]{4,12}\b/gi,
		replacement: '[REDACTED-PATIENT-ID]',
	},
	{
		id: 'encounter-id',
		name: 'Encounter ID',
		description: 'Healthcare encounter identifiers',
		regex: /\b(ENC|ENCOUNTER)[-:]?\s*[A-Z0-9]{4,12}\b/gi,
		replacement: '[REDACTED-ENCOUNTER-ID]',
	},
	{
		id: 'claim-number',
		name: 'Claim Number',
		description: 'Insurance claim numbers',
		regex: /\b(CLM|CL|CLAIM)[-:]?\s*[A-Z0-9]{6,15}\b/gi,
		replacement: '[REDACTED-CLAIM]',
	},
	{
		id: 'prescription-id',
		name: 'Prescription ID',
		description: 'Prescription identifiers',
		regex: /\b(RX|PRX)[-:]?\s*[A-Z0-9]{4,12}\b/gi,
		replacement: '[REDACTED-PRESCRIPTION]',
	},
	{
		id: 'insurance-id',
		name: 'Insurance ID',
		description: 'Health insurance policy identifiers',
		regex: /\b(BCBS|AETNA|HUMANA|POL)[-:]?\s*[A-Z0-9]{6,15}\b/gi,
		replacement: '[REDACTED-INSURANCE]',
	},
	{
		id: 'account-number',
		name: 'Account Number',
		description: 'Healthcare account numbers',
		regex: /\bACC#[A-Z0-9]{6,12}\b/gi,
		replacement: '[REDACTED-ACCOUNT]',
	},
	{
		id: 'device-id',
		name: 'Device ID',
		description: 'Medical device identifiers (UDI)',
		regex: /\bUDI[-:]?\s*[A-Z0-9]{8,15}\b/gi,
		replacement: '[REDACTED-DEVICE-ID]',
	},
] satisfies PIIRegex[]

function redactPII(input: string, patterns: PIIRegex[]): string {
	const regexes = patterns.map((regex) => ({
		...regex,
		regex: new RegExp(regex.regex.source, regex.regex.flags),
	}))
	return regexes.reduce((input, regex) => {
		return input.replace(regex.regex, regex.replacement)
	}, input)
}

type PIIGuardOptions = GuardOptions & {
	patterns?: PIIRegex[]
	mode?: 'block' | 'redact'
}

export function piiGuard(opts: PIIGuardOptions = {}): Guard {
	return makeGuard({
		...opts,
		id: 'pii',
		name: 'PII Guard',
		implementation: (input, msg, config, idx) => {
			const patterns = [...PII_REGEX_REGISTRY, ...(opts.patterns || [])]
			const mode = opts.mode || 'redact'
			const common = {
				guardId: config.id,
				guardName: config.name,
				message: msg.originalMessage,
				index: idx,
				passed: true,
				reason: 'No PII detected',
				messageHash: msg.messageHash,
				inScope: msg.inScope,
			}
			if (!msg.inScope) {
				return {
					...common,
					passed: true,
					reason: 'Message is not in scope',
				}
			}
			const redactedInput = redactPII(input, patterns)
			if (redactedInput !== input) {
				return {
					...common,
					passed: mode === 'block',
					reason: 'Input contains possible PII',
					modifiedMessage: {
						...msg.originalMessage,
						content: redactedInput,
					},
				}
			}
			return common
		},
	})
}
