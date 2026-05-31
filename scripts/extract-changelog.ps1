# 從 CHANGELOG.md 抽出指定版本的段落，寫入 release-body.md 供 Release 說明使用。
# 用法： pwsh -File scripts/extract-changelog.ps1 -Tag v1.0.0
param([Parameter(Mandatory=$true)][string]$Tag)

$changelog = Join-Path (Split-Path $PSScriptRoot -Parent) 'CHANGELOG.md'
$body = "StillGuard $Tag"

if (Test-Path $changelog) {
    $lines = Get-Content -LiteralPath $changelog -Encoding utf8
    $out = New-Object System.Collections.Generic.List[string]
    $inSection = $false
    $escaped = [regex]::Escape($Tag)
    foreach ($line in $lines) {
        if ($line -match '^##\s+') {
            if ($inSection) { break }                                   # 下一個版本標題 → 結束
            if ($line -match ("^##\s+" + $escaped + '(\s|$)')) { $inSection = $true }
            continue
        }
        if ($inSection) { $out.Add($line) }
    }
    $joined = ($out -join "`n").Trim()
    if ($joined) { $body = $joined }
}

$target = Join-Path (Split-Path $PSScriptRoot -Parent) 'release-body.md'
Set-Content -LiteralPath $target -Value $body -Encoding utf8
Write-Output "release-body.md 已產生（版本 $Tag）："
Write-Output $body
