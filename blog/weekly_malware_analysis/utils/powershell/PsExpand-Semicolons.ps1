param(
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$OutputFile,
    [string]$IndentString = '    '
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_PsDeobLib.ps1"
try {
    $stats = Invoke-PsExpandSemicolons -InputPath $InputFile `
                                        -OutputPath $OutputFile `
                                        -IndentString $IndentString
    $stats | ConvertTo-Json -Compress
} catch {
    "ERROR: $($_.Exception.Message)" | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline
}
