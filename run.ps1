#requires -version 5.1
<#
.SYNOPSIS
  Windows 微信 4.x 聊天记录解密与导出。

.DESCRIPTION
  默认流程：检测数据目录 → 只读抓取密钥（Config.Cipher）→ 数据快照 →
  密钥映射 → 解密 → 导出 TXT/CSV/JSON。不会向微信注入代码。

.EXAMPLE
  .\run.ps1
  .\run.ps1 -NoHunt -Output D:\WeChat-Export
  .\run.ps1 -Passphrase <64位hex>
  .\run.ps1 -RefreshSnapshot -Output D:\WeChat-Export
#>
[CmdletBinding()]
param(
    [switch]$NoHunt,
    [switch]$NoRestart,
    [switch]$RefreshSnapshot,
    [string]$Output = "",
    [string]$DbDir = "",
    [string]$Passphrase = "",
    [string]$KeyFile = "",
    [string[]]$DbKey = @(),
    [switch]$Deep,
    [switch]$Inject,
    [switch]$NoSnapshot,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    try {
        chcp 65001 | Out-Null
        [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
    } catch {}

    if ($NoHunt -and $NoRestart) {
        throw "--NoHunt 与 --NoRestart 不能同时使用"
    }
    if ($RefreshSnapshot -and $NoHunt) {
        throw "--RefreshSnapshot 需要完整抓取，不能与 --NoHunt 同时使用"
    }
    if ($Inject -and $NoHunt) {
        throw "--Inject 需要完整抓取，不能与 --NoHunt 同时使用"
    }
    if ($Yes) {
        $env:WXEXPORT_NONINTERACTIVE = "1"
    }
    $env:PYTHONIOENCODING = "utf-8"
    $src = Join-Path $root "src"
    $existingPath = $env:PYTHONPATH
    if ($existingPath) {
        $env:PYTHONPATH = "$src;$existingPath"
    } else {
        $env:PYTHONPATH = $src
    }

    $python = Join-Path $root ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) {
        if (Get-Command uv -ErrorAction SilentlyContinue) {
            Write-Host "[*] 使用 uv 创建虚拟环境 ..."
            & uv sync --frozen
            if ($LASTEXITCODE -ne 0) {
                throw "uv sync 失败（退出码 $LASTEXITCODE）"
            }
        } else {
            $systemPython = Get-Command python -ErrorAction SilentlyContinue
            if (-not $systemPython) {
                throw "未找到 Python。请安装 Python 3.10+ 或 uv。"
            }
            Write-Host "[*] 未找到 uv，使用 venv + pip ..."
            & python -m venv .venv
            if ($LASTEXITCODE -ne 0) { throw "创建虚拟环境失败" }
            & $python -m pip install --upgrade pip
            & $python -m pip install -e .
            if ($LASTEXITCODE -ne 0) { throw "安装依赖失败" }
        }
    }
    if (-not (Test-Path $python)) {
        throw "虚拟环境创建后仍未找到 $python"
    }
    & $python -c "import wxexport, Crypto, zstandard" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[*] 虚拟环境缺少依赖，重新安装 ..."
        if (Get-Command uv -ErrorAction SilentlyContinue) {
            & uv sync --frozen
        } else {
            & $python -m pip install -e .
        }
        if ($LASTEXITCODE -ne 0) { throw "依赖安装失败" }
    }

    function Invoke-Py {
        param(
            [string[]]$PyArgs,
            [int[]]$Allow = @(0),
            [string]$Label = ""
        )
        if (-not $Label) { $Label = ($PyArgs | Select-Object -First 3) -join " " }
        Write-Host "[*] $Label"
        & $python @PyArgs
        $code = $LASTEXITCODE
        if ($Allow -notcontains $code) {
            throw "命令失败（退出码 $code）: $Label"
        }
    }

    Invoke-Py -PyArgs @("-m", "wxexport.check_permissions") -Label "检查数据目录与进程权限"

    if (-not $NoHunt) {
        $huntArgs = @("-m", "wxexport.keys.hunt")
        if ($DbDir) { $huntArgs += @("--db-dir", $DbDir) }
        if ($Passphrase) { $huntArgs += @("--passphrase", $Passphrase) }
        if ($KeyFile) { $huntArgs += @("--key-file", $KeyFile) }
        foreach ($item in $DbKey) {
            if ($item) { $huntArgs += @("--key", $item) }
        }
        if ($Deep) { $huntArgs += "--deep" }
        if ($Inject) { $huntArgs += "--inject" }
        if ($NoSnapshot) { $huntArgs += "--no-snapshot" }
        if ($RefreshSnapshot) { $huntArgs += "--refresh-snapshot" }
        if ($NoRestart) { $huntArgs += "--no-restart" }
        Invoke-Py -PyArgs $huntArgs -Allow @(0, 3) -Label "抓取并验证数据库密钥"
    } else {
        Write-Host "[*] 跳过密钥抓取，复用已有 all_keys.json"
    }

    $mapArgs = @("-m", "wxexport.keys.map")
    if ($DbDir) { $mapArgs += @("--db-dir", $DbDir) }
    if ($Passphrase) { $mapArgs += @("--passphrase", $Passphrase) }
    if ($KeyFile) { $mapArgs += @("--key-file", $KeyFile) }
    Invoke-Py -PyArgs $mapArgs -Label "映射密钥"

    $decryptArgs = @("-m", "wxexport.decrypt")
    if ($DbDir) { $decryptArgs += @("--db-dir", $DbDir) }
    Invoke-Py -PyArgs $decryptArgs -Label "解密数据库"

    if (-not $Output) {
        $Output = Join-Path $root "exported_all"
    }
    Invoke-Py -PyArgs @("-m", "wxexport.export.all", "--output", $Output) -Label "导出聊天记录"

    $resolved = [System.IO.Path]::GetFullPath($Output)
    Write-Host ""
    Write-Host "============================================================"
    Write-Host " 完成。聊天记录在: $resolved"
    Write-Host " 总索引:          $(Join-Path $resolved 'index.csv')"
    Write-Host "============================================================"
}
finally {
    Pop-Location
}
