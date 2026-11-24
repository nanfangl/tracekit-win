<#
一键推送脚本：初始化仓库、提交、加远端并推送。

用法（在本目录，PowerShell）：
    # 1. 先装 git（没装的话）
    winget install --id Git.Git -e

    # 2. 推送（需要一个带 repo + workflow 权限的 PAT，见 README 的「上传到 GitHub」一节）
    powershell -ExecutionPolicy Bypass -File push.ps1 -RepoUrl https://github.com/<你的用户名>/tracekit-win.git

    # 已经有仓库、只想更新：
    powershell -ExecutionPolicy Bypass -File push.ps1 -RepoUrl <同地址> -Message "fix: xxx"
#>
param(
    [string]$RepoUrl = "",
    [string]$Branch = "main",
    [string]$Message = "",
    [string]$UserName = "",
    [string]$UserEmail = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Fail($msg) { Write-Host "`n[x] $msg" -ForegroundColor Red; exit 1 }

Write-Host "=== 1/6 检查 git ==="
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) {
    Fail "没有 git。先执行：winget install --id Git.Git -e   （装完重开一个终端）"
}
git --version

Write-Host "=== 2/6 检查提交身份 ==="
$name = git config user.name
$email = git config user.email
if (-not $name -or -not $email) {
    if (-not $UserName -or -not $UserEmail) {
        Fail "没有 git 提交身份。请带上参数重试：-UserName ""你的名字"" -UserEmail ""you@example.com"""
    }
    git config --local user.name $UserName
    git config --local user.email $UserEmail
}
Write-Host ("  提交身份: {0} <{1}>" -f (git config user.name), (git config user.email))

Write-Host "=== 3/6 初始化仓库 ==="
if (-not (Test-Path ".git")) {
    git init -b $Branch | Out-Null
    Write-Host "  已初始化（分支 $Branch）"
} else {
    Write-Host "  已是 git 仓库，跳过"
}

Write-Host "=== 4/6 提交 ==="
git add -A
$staged = git diff --cached --name-only
if (-not $staged) {
    Write-Host "  没有改动需要提交"
} else {
    if (-not $Message) { $Message = "chore: update TraceKit" }
    git commit -m $Message | Out-Null
    Write-Host ("  已提交 {0} 个文件" -f ($staged | Measure-Object).Count)
}

Write-Host "=== 5/6 配置远端 ==="
if (-not $RepoUrl) {
    $RepoUrl = Read-Host "请输入 GitHub 仓库地址（例如 https://github.com/me/tracekit-win.git）"
}
if (-not $RepoUrl) { Fail "仓库地址为空" }
$remotes = git remote
if ($remotes -match "origin") {
    git remote set-url origin $RepoUrl
    Write-Host "  已更新 origin -> $RepoUrl"
} else {
    git remote add origin $RepoUrl
    Write-Host "  已添加 origin -> $RepoUrl"
}

Write-Host "=== 6/6 推送 ==="
Write-Host "  提示：密码处要填 Personal Access Token，不是账号密码"
git push -u origin $Branch
if ($LASTEXITCODE -ne 0) { Fail "推送失败。检查：令牌是否有 repo 权限、仓库是否已创建、网络是否可达 github.com" }

Write-Host "`n[√] 完成。仓库：$RepoUrl" -ForegroundColor Green
Write-Host "    下一步：在 GitHub 上建 Release，把 dist\TraceKit.exe 作为附件上传（36MB 超过网页直传上限，走 Release 附件没问题）"
