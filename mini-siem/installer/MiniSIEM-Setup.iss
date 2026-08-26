; Inno Setup 6 — Mini-SIEM tam kurulum (Electron + gömülü Python API)
; Önkoşul: backend venv'te pip install -r requirements.txt -r requirements-build.txt
; Derleme:  cd desktop  &&  npm install  &&  npm run build:win:full
; (PyInstaller dist + electron-builder win-unpacked; API uygulama açılışında otomatik başlar)
; Bu .iss, installer klasöründen derlenir; kaynak: ..\desktop\release\win-unpacked

#define MyAppName "Mini-SIEM Desktop"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Mini-SIEM"
#define MyAppExeName "Mini-SIEM Desktop.exe"
#define SourceUnpacked "..\\desktop\\release\\win-unpacked"

[Setup]
AppId={{A8F3E2B1-4C5D-6E7F-8091-A2B3C4D5E6F7}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=MiniSIEM-Desktop-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceUnpacked}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
