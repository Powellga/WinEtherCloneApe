# Builds the two release files into .\artifacts:
#   WinEtherCloneApe-<version>-portable.exe  single exe, .NET runtime included, just run it
#   WinEtherCloneApe-<version>-Setup.exe     installer (Start Menu, uninstaller, WebView2, Npcap check)
# Requires Inno Setup 6 (winget install JRSoftware.InnoSetup --scope user).

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$artifacts = Join-Path $root 'artifacts'
$version = ([xml](Get-Content (Join-Path $root 'WinEtherCloneApe.csproj'))).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
Write-Host "Building WinEtherCloneApe $version"

# 1. Self-contained single-file exe
$portableDir = Join-Path $artifacts 'portable'
dotnet publish (Join-Path $root 'WinEtherCloneApe.csproj') -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none -o $portableDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
$portableExe = Join-Path $portableDir 'WinEtherCloneApe.exe'
Copy-Item $portableExe (Join-Path $artifacts "WinEtherCloneApe-$version-portable.exe") -Force

# 2. WebView2 bootstrapper (Microsoft's redistributable, ~2 MB) for the installer
$redist = Join-Path $root 'installer\redist'
$bootstrapper = Join-Path $redist 'MicrosoftEdgeWebview2Setup.exe'
if (-not (Test-Path $bootstrapper)) {
    New-Item -ItemType Directory -Force $redist | Out-Null
    Invoke-WebRequest 'https://go.microsoft.com/fwlink/p/?LinkId=2124703' -OutFile $bootstrapper -UseBasicParsing
}

# 3. Installer
$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found. Install it with: winget install JRSoftware.InnoSetup --scope user" }
& $iscc /Q "/DMyAppVersion=$version" "/DPortableExe=$portableExe" (Join-Path $root 'installer\WinEtherCloneApe.iss')
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

Get-ChildItem $artifacts -File | Select-Object Name, @{ n = 'MB'; e = { [math]::Round($_.Length / 1MB, 1) } }
