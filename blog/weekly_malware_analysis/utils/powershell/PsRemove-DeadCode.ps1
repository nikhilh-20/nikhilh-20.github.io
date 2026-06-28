param(
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$OutputFile
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_PsDeobLib.ps1"
try {
    $stats = Invoke-PsRemoveDeadCode `
        -InputPath              $InputFile `
        -OutputPath             $OutputFile `
        -PreserveStringLiterals $true
    $stats | ConvertTo-Json -Compress
} catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
}
