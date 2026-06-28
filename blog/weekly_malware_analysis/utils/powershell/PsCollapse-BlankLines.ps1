param(
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$OutputFile
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_PsDeobLib.ps1"
try {
    $stats = Invoke-PsCollapseBlankLines -InputPath $InputFile -OutputPath $OutputFile
    $stats | ConvertTo-Json -Compress
} catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
}
