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
; Inbound firewall rules, scoped to these two programs and the Private network
; profile only. Without them Windows shows a one-time prompt on first run and,
; if it's dismissed or answered "public only", phones can never reach this PC
; (TCP 45990 for packets, UDP 45991 for discovery) -- the most likely silent
; failure of a first real-device test. Idempotent: delete first, then add.
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Rin (RinWindows.exe)"""; Flags: runhidden; StatusMsg: "Configuring firewall..."
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Rin (RinWindows.exe)"" dir=in action=allow program=""{app}\RinWindows.exe"" enable=yes profile=private"; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Rin (rin-console.exe)"""; Flags: runhidden
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall add rule name=""Rin (rin-console.exe)"" dir=in action=allow program=""{app}\rin-console.exe"" enable=yes profile=private"; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: postinstall skipifsilent nowait

[UninstallRun]
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Rin (RinWindows.exe)"""; Flags: runhidden; RunOnceId: "RinFwGui"
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=""Rin (rin-console.exe)"""; Flags: runhidden; RunOnceId: "RinFwConsole"
