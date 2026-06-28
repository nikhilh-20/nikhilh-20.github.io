param(
    [Parameter(Mandatory)][string]$InputFile
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_PsDeobLib.ps1"
try {
    $result = Invoke-PsExtractVariables -InputPath $InputFile
    $result | ConvertTo-Json -Compress -Depth 6
} catch {
    "ERROR: $($_.Exception.Message)"
}
