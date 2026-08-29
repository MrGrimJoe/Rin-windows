; Rin (Windows) — Inno Setup installer
; RinWindows.exe is built statically linked (vcpkg x64-windows-static
; triplet + /MT CRT, see .github/workflows/build.yml) specifically so this
; installer doesn't need to bundle or chase down any OpenSSL/libqrencode/
; MSVC runtime DLLs -- one exe, copied as-is.

#define MyAppName "Rin"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "MrGrimJoe"
#define MyAppExeName "RinWindows.exe"

#define MyBuildTag GetEnv("GITHUB_RUN_NUMBER")
#if MyBuildTag == ""
  #define MyBuildTag "local"
#endif

[Setup]
AppId={{5E7C3A1F-2B6D-4E9A-9C3F-1A8B6D4E7F20}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequired=admin
OutputDir=dist
OutputBaseFilename=Rin-Setup-{#MyAppVersion}-build{#MyBuildTag}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; build\Release\ is where CMake --config Release puts single-config-generator
; output on the multi-config Visual Studio generator used in CI.
Source: "build\Release\RinWindows.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "build\Release\rin-console.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: postinstall skipifsilent nowait
