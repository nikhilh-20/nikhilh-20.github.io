param(
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$OutputFile,
    [Parameter(Mandatory)][string]$Pattern,
    [Parameter(Mandatory)][string]$Flags
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_PsDeobLib.ps1"
try {
    $stats = Invoke-PsStripLines -InputPath $InputFile `
                                  -OutputPath $OutputFile `
                                  -Pattern $Pattern `
                                  -Flags $Flags
    $stats | ConvertTo-Json -Compress
} catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
}
