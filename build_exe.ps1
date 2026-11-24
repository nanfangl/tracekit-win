<#
打包单文件 EXE（TraceKit.exe + 内置演示靶 TraceKitDemo.exe）

用法（在仓库根目录）：
    powershell -ExecutionPolicy Bypass -File build_exe.ps1

产物：
    dist\TraceKit.exe       主程序（双击 = 向导）
    dist\TraceKitDemo.exe   演示靶（可选，用于 selftest / 试跑）

要求：Python 3.9+，pip install pyinstaller（以及可选 pillow 用于截图）
#>
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[1/4] 检查依赖 ..."
python -m pip install --quiet --upgrade pyinstaller

Write-Host "[2/4] 生成图标（可选，缺 Pillow 就跳过）..."
if (Test-Path "assets\tracekit.ico") {
    Write-Host "      已有 assets\tracekit.ico"
} else {
    try { python tools\make_icon.py } catch { Write-Host "      跳过图标" }
}

Write-Host "[3/4] 打包演示靶 TraceKitDemo.exe ..."
python -m PyInstaller --noconfirm --clean --onefile --console `
    --name TraceKitDemo --distpath dist --workpath build_demo demo_victim.py

Write-Host "[4/4] 打包主程序 TraceKit.exe ..."
$icon = if (Test-Path "assets\tracekit.ico") { @("--icon", "assets\tracekit.ico") } else { @() }
python -m PyInstaller --noconfirm --clean --onefile --console --name TraceKit @icon `
    --paths . `
    --collect-submodules tracekit `
    --collect-submodules tkinter `
    --hidden-import tracekit.mod_etw --hidden-import tracekit.report `
    --hidden-import tracekit.mod_uiact --hidden-import tracekit.gui `
    --hidden-import tracekit.mod_uitree --hidden-import tracekit.mod_filesnap `
    --hidden-import tracekit.mod_modules --hidden-import tracekit.mod_sys `
    --hidden-import tracekit.mod_dns `
    --hidden-import PIL.Image --hidden-import PIL.ImageGrab --hidden-import PIL._imaging `
    --hidden-import tkinter --hidden-import tkinter.filedialog `
    --hidden-import tkinter.messagebox --hidden-import tkinter.simpledialog `
    --hidden-import tkinter.ttk `
    --add-data "demo_victim.py;." `
    --add-data "dist/TraceKitDemo.exe;." `
    TraceKit_main.py

Write-Host ""
Get-ChildItem dist\*.exe | ForEach-Object { "{0}  {1:N1} MB" -f $_.Name, ($_.Length / 1MB) }
Write-Host "完成。自测： .\dist\TraceKit.exe selftest --no-etw"
