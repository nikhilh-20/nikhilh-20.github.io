param(
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$OutputFile,
    [Parameter(Mandatory)][string]$RenamesFile
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_PsDeobLib.ps1"
try {
    $renameMap = @{}
    (Get-Content -Path $RenamesFile -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $renameMap[$_.Name] = $_.Value }
    $stats = Invoke-PsRenameVariables -InputPath $InputFile -OutputPath $OutputFile -Renames $renameMap
    $stats | ConvertTo-Json -Compress -Depth 3
} catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
}
