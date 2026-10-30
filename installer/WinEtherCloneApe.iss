; Inno Setup script for WinEtherCloneApe
; Built by build-release.ps1, which passes MyAppVersion and PortableExe.

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#ifndef PortableExe
  #define PortableExe "..\artifacts\portable\WinEtherCloneApe.exe"
#endif

#define MyAppName "WinEtherCloneApe"
#define MyAppExe "WinEtherCloneApe.exe"
#define MyAppUrl "https://github.com/Powellga/WinEtherCloneApe"

[Setup]
AppId={{6E2B7C1A-3F5D-4B8E-9A21-7C0D4E5F8A93}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=Gregg Powell
AppPublisherURL={#MyAppUrl}
AppSupportURL={#MyAppUrl}/issues
AppUpdatesURL={#MyAppUrl}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Installs for the current user without an admin prompt; the dialog lets them choose "all users" instead
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir=..\artifacts
OutputBaseFilename={#MyAppName}-{#MyAppVersion}-Setup
SetupIconFile=..\app.ico
UninstallDisplayIcon={app}\{#MyAppExe}
LicenseFile=..\LICENSE.txt
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[InstallDelete]
; Clean out the older multi-file layout (v2.0.0 zip) if it was unzipped into the same folder
Type: files; Name: "{app}\*.dll"
Type: files; Name: "{app}\*.pdb"
Type: files; Name: "{app}\*.xml"
Type: files; Name: "{app}\*.deps.json"
Type: files; Name: "{app}\*.runtimeconfig.json"
Type: filesandordirs; Name: "{app}\runtimes"

[Files]
Source: "{#PortableExe}"; DestDir: "{app}"; DestName: "{#MyAppExe}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "redist\MicrosoftEdgeWebview2Setup.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: not WebView2Installed

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; StatusMsg: "Installing Microsoft Edge WebView2 (used for maps)..."; Check: not WebView2Installed; Flags: waituntilterminated
Filename: "https://npcap.com/#download"; Description: "Open the Npcap download page (REQUIRED for packet capture)"; Flags: postinstall shellexec nowait; Check: not NpcapInstalled
Filename: "https://nmap.org/download#windows"; Description: "Open the Nmap download page (optional, adds Zenmap scans)"; Flags: postinstall shellexec nowait unchecked; Check: not ZenmapInstalled
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: postinstall shellexec nowait skipifsilent; Check: NpcapInstalled

[UninstallDelete]
; Caches only - settings.json and threats.log are kept
Type: filesandordirs; Name: "{localappdata}\WinEtherCloneApe\threatfeeds"
Type: filesandordirs; Name: "{localappdata}\WinEtherCloneApe\WebView2"
Type: filesandordirs; Name: "{localappdata}\WinEtherCloneApe\map"

[Code]
var
  NpcapPage: TOutputMsgWizardPage;

function NpcapInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM64, 'SOFTWARE\Npcap')
    or RegKeyExists(HKLM32, 'SOFTWARE\Npcap')
    or FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll'));
end;

function ZenmapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf32}\Nmap\zenmap.exe'))
    or FileExists(ExpandConstant('{commonpf64}\Nmap\zenmap.exe'));
end;

function WebView2VersionOk(RootKey: Integer; SubKey: String): Boolean;
var
  Version: String;
begin
  Result := RegQueryStringValue(RootKey, SubKey, 'pv', Version)
    and (Version <> '') and (Version <> '0.0.0.0');
end;

function WebView2Installed: Boolean;
var
  ClientKey: String;
begin
  ClientKey := 'Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  Result := WebView2VersionOk(HKLM32, 'SOFTWARE\' + ClientKey)
    or WebView2VersionOk(HKLM64, 'SOFTWARE\' + ClientKey)
    or WebView2VersionOk(HKCU, 'Software\' + ClientKey);
end;

procedure InitializeWizard;
begin
  if not NpcapInstalled then
  begin
    NpcapPage := CreateOutputMsgPage(wpWelcome,
      'Npcap is needed',
      'WinEtherCloneApe uses the free Npcap driver to see network traffic.',
      'Npcap is not installed on this PC yet.' + #13#10#13#10 +
      'Setup will continue now. When it finishes, tick "Open the Npcap download page", ' +
      'download Npcap from npcap.com and install it (keep "WinPcap API-compatible Mode" ticked).' + #13#10#13#10 +
      'Then start WinEtherCloneApe from the Start Menu.');
  end;
end;
