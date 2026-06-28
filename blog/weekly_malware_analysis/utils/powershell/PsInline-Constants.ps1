param(
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$OutputFile,
    [Parameter(Mandatory)][int]$MaxUses
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_PsDeobLib.ps1"
try {
    $result = Invoke-PsInlineConstants -InputPath $InputFile -OutputPath $OutputFile -MaxUses $MaxUses
    $result | ConvertTo-Json -Compress -Depth 3
} catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
}
