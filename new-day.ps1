<#
.SYNOPSIS
    Cree le dossier du jour a partir du template et prepare le commit.
.EXAMPLE
    .\new-day.ps1 -Day 2
    .\new-day.ps1 -Day 2 -Push
#>
param(
    [Parameter(Mandatory = $true)][int]$Day,
    [switch]$Push
)

$ErrorActionPreference = "Stop"
$root   = $PSScriptRoot
$num    = "{0:D3}" -f $Day          # 2 -> "002"
$folder = Join-Path $root "Day-$num"

if (Test-Path $folder) {
    Write-Host "[!] Le dossier Day-$num existe deja : $folder" -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Path $folder | Out-Null
New-Item -ItemType Directory -Path (Join-Path $folder "screenshots") | Out-Null

$template = Get-Content (Join-Path $root "_templates\README-template.md") -Raw
$template = $template -replace "Day XXX", "Day $num"
$template = $template -replace "AAAA-MM-JJ", (Get-Date -Format "yyyy-MM-dd")
Set-Content -Path (Join-Path $folder "README.md") -Value $template -Encoding utf8

Write-Host "[+] Dossier Day-$num cree : $folder" -ForegroundColor Green
Write-Host "    -> Redige Day-$num\README.md puis lance :  git add . ; git commit -m 'Day $num' ; git push"

if ($Push) {
    git -C $root add .
    git -C $root commit -m "Day $num : nouveau lab"
    git -C $root push
    Write-Host "[+] Pousse sur GitHub." -ForegroundColor Green
}
