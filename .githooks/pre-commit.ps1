$ErrorActionPreference = "Stop"

$blockedNames = '(?i)(^|/)(\.env($|\.)|\.npmrc$|\.pypirc$|\.netrc$|_netrc$|id_rsa|id_ed25519|.*(?:secret|credential|token|password).*)'
$secretPatterns = @(
    '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
    '\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})\b',
    '\bglpat-[A-Za-z0-9_-]{20,}\b',
    '\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b',
    '\bsk-ant-[A-Za-z0-9_-]{20,}\b',
    '\bAIza[0-9A-Za-z_-]{20,}\b',
    '\b(?:AKIA|ASIA)[0-9A-Z]{16}\b',
    '\bxox[baprs]-[A-Za-z0-9-]{10,}\b',
    '\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b',
    '\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b',
    '\bpypi-[A-Za-z0-9_-]{20,}\b',
    '\bnpm_[A-Za-z0-9]{20,}\b',
    '\bhf_[A-Za-z0-9]{20,}\b',
    '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b',
    '(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}',
    '(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@',
    '(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|private[_-]?key|account[_-]?key)\b\s*[:=]\s*["''][^"'']{4,}["'']'
)

$findings = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$stagedFiles = @(git diff --cached --name-only --diff-filter=ACMR)

foreach ($path in $stagedFiles) {
    if ($path -in @('.githooks/pre-commit', '.githooks/pre-commit.ps1')) {
        continue
    }

    if ($path -match $blockedNames) {
        [void]$findings.Add($path)
        continue
    }

    $content = (git show ":$path" 2>$null | Out-String)
    foreach ($pattern in $secretPatterns) {
        if ($content -match $pattern) {
            [void]$findings.Add($path)
            break
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Error ("Commit blocked: possible secret material in " + (($findings | Sort-Object) -join ', '))
    exit 1
}

exit 0
