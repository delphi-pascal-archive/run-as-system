unit RunAsSystem;

interface

uses
  Windows, SysUtils, TLHelp32, AccCtrl, AclAPI;

var
  WindowsVersion: Cardinal;  

type
  TIntegrityLevel = (UnknownIntegrityLevel, LowIntegrityLevel, MediumIntegrityLevel, HighIntegrityLevel, SystemIntegrityLevel);

  PStartupInfoW = ^TStartupInfoW;
  _STARTUPINFOW = record
    cb: DWORD;
    lpReserved: PWideChar;
    lpDesktop: PWideChar;
    lpTitle: PWideChar;
    dwX: DWORD;
    dwY: DWORD;
    dwXSize: DWORD;
    dwYSize: DWORD;
    dwXCountChars: DWORD;
    dwYCountChars: DWORD;
    dwFillAttribute: DWORD;
    dwFlags: DWORD;
    wShowWindow: Word;
    cbReserved2: Word;
    lpReserved2: PByte;
    hStdInput: THandle;
    hStdOutput: THandle;
    hStdError: THandle;
  end;
  _STARTUPINFO = _STARTUPINFOW;
  TStartupInfoW = _STARTUPINFOW;

  TTokenInformationClass = (
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids, 
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    vMaxTokenInfoClass);

function CreateProcessAsSystemW(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel): Boolean; overload;

function CreateProcessAsSystemW(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation): Boolean; overload;

implementation

const
  LOW_INTEGRITY_SID: PWideChar = 'S-1-16-4096';
  MEDIUM_INTEGRITY_SID: PWideChar = 'S-1-16-8192';
  HIGH_INTEGRITY_SID: PWideChar = 'S-1-16-12288';
  SYSTEM_INTEGRITY_SID: PWideChar = 'S-1-16-16384';

  SECURITY_MANDATORY_UNTRUSTED_RID = $00000000;
  SECURITY_MANDATORY_LOW_RID = $00001000;
  SECURITY_MANDATORY_MEDIUM_RID = $00002000;
  SECURITY_MANDATORY_HIGH_RID = $00003000;
  SECURITY_MANDATORY_SYSTEM_RID = $00004000;
  SECURITY_MANDATORY_PROTECTED_PROCESS_RID = $00005000;

  SE_GROUP_INTEGRITY = $00000020;

type
  _TOKEN_MANDATORY_LABEL = record
    Label_: SID_AND_ATTRIBUTES;
  end;

  TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL;
  PTOKEN_MANDATORY_LABEL = ^TOKEN_MANDATORY_LABEL;

  TTokenMandatoryLabel = _TOKEN_MANDATORY_LABEL;
  PTokenMandatoryLabel = ^TTokenMandatoryLabel;

  TConvertStringSidToSidW = function(StringSid: PWideChar; var Sid: PSID): BOOL; stdcall;
  TCreateProcessWithTokenW = function(hToken: THandle;
    dwLogonFlags: DWORD;
    lpApplicationName: PWideChar;
    lpCommandLine: PWideChar;
    dwCreationFlags: DWORD;
    lpEnvironment: Pointer;
    lpCurrentDirectory: PWideChar;
    lpStartupInfo: PStartupInfoW;
    lpProcessInformation: PProcessInformation): BOOL; stdcall;

  TConvertStringSidToSidA = function(StringSid: PAnsiChar; var Sid: PSID): BOOL; stdcall;

  TGetTokenInformation = function(TokenHandle: THandle;
    TokenInformationClass: TTokenInformationClass; TokenInformation: Pointer;
    TokenInformationLength: DWORD; var ReturnLength: DWORD): BOOL; stdcall;

  TSetTokenInformation = function(TokenHandle: THandle;
    TokenInformationClass: TTokenInformationClass; TokenInformation: Pointer;
    TokenInformationLength: DWORD): BOOL; stdcall;

  TCreateProcessAsUserW = function(hToken: THandle; lpApplicationName: PWideChar;
    lpCommandLine: PWideChar; lpProcessAttributes: PSecurityAttributes;
    lpThreadAttributes: PSecurityAttributes; bInheritHandles: BOOL;
    dwCreationFlags: DWORD; lpEnvironment: Pointer; lpCurrentDirectory: PWideChar;
    const lpStartupInfo: TStartupInfoW; var lpProcessInformation: TProcessInformation): BOOL; stdcall;

var
  ConvertStringSidToSidW: TConvertStringSidToSidW;
  CreateProcessWithTokenW: TCreateProcessWithTokenW;
  ConvertStringSidToSidA: TConvertStringSidToSidA;
  GetTokenInformation: TGetTokenInformation;
  SetTokenInformation: TSetTokenInformation;
  CreateProcessAsUserW: TCreateProcessAsUserW;

function GetWindowsVersion: Cardinal;
var
  OSVersionInfo: TOSVersionInfo;
begin
  Result := 0;
  FillChar(OSVersionInfo, SizeOf(TOSVersionInfo), 0);
  OSVersionInfo.DwOSVersionInfoSize := SizeOf(TOSVersionInfo);
  if GetVersionEx(OSVersionInfo) then
  begin
    if OSVersionInfo.dwMajorVersion = 5 then
    begin
      if OSVersionInfo.dwMinorVersion = 0 then
        Result := 50 // 2000
      else if OSVersionInfo.dwMinorVersion = 2 then
        Result := 52 // 2003
      else if OSVersionInfo.dwMinorVersion = 1 then
        Result := 51 // XP
    end;
    if OSVersionInfo.dwMajorVersion = 6 then
    begin
      if OSVersionInfo.dwMinorVersion = 0 then
        Result := 60 // Vista
      else if OSVersionInfo.dwMinorVersion = 1 then
        Result := 61; // 7
    end;
  end;
end;

function AdjustCurrentProcessPrivilege(PrivilegeName: WideString; Enabled: Boolean): Boolean;
var
  TokenHandle: THandle;
  TokenPrivileges: TTokenPrivileges;
  ReturnLength: DWORD;
begin
  Result := False;
  try
    if OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, TokenHandle) then
    begin
      try
        LookupPrivilegeValueW(nil, PWideChar(PrivilegeName), TokenPrivileges.Privileges[0].Luid);
        TokenPrivileges.PrivilegeCount := 1;
        if Enabled then
          TokenPrivileges.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED
        else
          TokenPrivileges.Privileges[0].Attributes := 0;
        if AdjustTokenPrivileges(TokenHandle, False, TokenPrivileges, 0, nil, ReturnLength) then
          Result := True;
      finally
        CloseHandle(TokenHandle);
      end;
    end;
  except
  end;
end;

function GetProcessIntegrityLevel(ProcessId: DWORD; var IntegrityLevel: TIntegrityLevel): Boolean;
var
  SIDAndAttributes: PSIDAndAttributes;
  i: DWORD;
  ReturnLength: DWORD;
  SidSubAuthorityCount: PUCHAR;
  SidSubAuthority: DWORD;
  ProcessHandle, TokenHandle: THandle;
begin
  IntegrityLevel := UnknownIntegrityLevel;
  Result := False;
  try
    ProcessHandle := 0;
    ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, ProcessId);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            GetTokenInformation(TokenHandle, TokenIntegrityLevel, nil, 0, ReturnLength);
            SIDAndAttributes := nil;
            GetMem(SIDAndAttributes, ReturnLength);
            if SIDAndAttributes <> nil then
            begin
              try
                if GetTokenInformation(TokenHandle, TokenIntegrityLevel, SIDAndAttributes, ReturnLength, ReturnLength) then
                begin
                  SidSubAuthorityCount := GetSidSubAuthorityCount(SIDAndAttributes.Sid);
                  SidSubAuthority := SidSubAuthorityCount^;
                  SidSubAuthority := SidSubAuthority - 1;
                  if IsValidSid(SIDAndAttributes.Sid) then
                  begin
                    case DWORD(GetSidSubAuthority(SIDAndAttributes.Sid, SidSubAuthority)^) of
                      SECURITY_MANDATORY_LOW_RID:
                        IntegrityLevel := LowIntegrityLevel;
                      SECURITY_MANDATORY_MEDIUM_RID:
                        IntegrityLevel := MediumIntegrityLevel;
                      SECURITY_MANDATORY_HIGH_RID:
                        IntegrityLevel := HighIntegrityLevel;
                      SECURITY_MANDATORY_SYSTEM_RID:
                        IntegrityLevel := SystemIntegrityLevel;
                    end;
                    Result := True;
                  end;
                end;
              finally
                FreeMem(SIDAndAttributes, ReturnLength);
              end;
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;

function GetTokenUserName(ProcessId: DWORD; var UserName: WideString; var DomainName: WideString): Boolean;
var
  ReturnLength: DWORD;
  peUse: SID_NAME_USE;
  SIDAndAttributes: PSIDAndAttributes;
  Name: PWideChar;
  Domain: PWideChar;
  ProcessHandle, TokenHandle: THandle;
begin
  Result := False;
  try
    ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, ProcessId);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            GetTokenInformation(TokenHandle, TokenUser, nil, 0, ReturnLength);
            GetMem(SIDAndAttributes, ReturnLength);
            if SIDAndAttributes <> nil then
            begin
              try
                if GetTokenInformation(TokenHandle, TokenUser, SIDAndAttributes, ReturnLength, ReturnLength) then
                begin
                  GetMem(Name, MAX_PATH);
                  GetMem(Domain, MAX_PATH);
                  if (Name <> nil) and (Domain <> nil) then
                  begin
                    try
                      if LookupAccountSidW(nil, SIDAndAttributes.SID, Name, ReturnLength, Domain, ReturnLength, peUse) then
                      begin
                        UserName := WideString(Name);
                        DomainName := WideString(Domain);
                        Result := True;
                      end;
                    finally
                      FreeMem(Name);
                      FreeMem(Domain);
                    end;
                  end;
                end;
              finally
                FreeMem(SIDAndAttributes, ReturnLength);
              end;
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;

function GetWinlogonProcessId: Cardinal;
var
  ToolHelp32SnapShot: THandle;
  ProcessEntry32: TProcessEntry32;
  IntegrityLevel: TIntegrityLevel;
  UserName: WideString;
  DomainName: WideString;
begin
  Result := 0;
  try
    ToolHelp32SnapShot := CreateToolHelp32SnapShot(TH32CS_SNAPPROCESS, 0);
    if ToolHelp32SnapShot <> INVALID_HANDLE_VALUE then
    begin
      try
        ProcessEntry32.dwSize := SizeOf(TProcessEntry32);
        while Process32Next(ToolHelp32SnapShot, ProcessEntry32) = True do
        begin
          if (LowerCase(ProcessEntry32.szExeFile) = 'winlogon.exe') then
          begin
            if WindowsVersion >= 60 then
            begin
              GetProcessIntegrityLevel(ProcessEntry32.th32ProcessID, IntegrityLevel);
              if IntegrityLevel = SystemIntegrityLevel then
              begin
                Result := ProcessEntry32.th32ProcessID;
                Break;
              end;
            end
            else
            begin
              GetTokenUserName(ProcessEntry32.th32ProcessID, UserName, DomainName);
              if UserName = 'SYSTEM' then
              begin
                Result := ProcessEntry32.th32ProcessID;
                Break;
              end;
            end;
          end;
        end;
      finally
        CloseHandle(ToolHelp32SnapShot);
      end;
    end;
  except
  end;
end;

function CreateProcessAsSystemW_Vista(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel): Boolean;
var
  ProcessHandle, TokenHandle, ImpersonateToken: THandle;
  Sid: PSID;
  MandatoryLabel: PTOKEN_MANDATORY_LABEL;
  ReturnLength: DWORD;
  PIntegrityLevel: PWideChar;
begin
  Result := False;
  if (@CreateProcessWithTokenW = nil) then
    Exit;
  try
    ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, GetWinlogonProcessId);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            if DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, ImpersonateToken) then
            begin
              try
                New(Sid);
                if (not GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, 0, ReturnLength)) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
                begin
                  MandatoryLabel := nil;
                  GetMem(MandatoryLabel, ReturnLength);
                  if MandatoryLabel <> nil then
                  begin
                    try
                      if GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, ReturnLength, ReturnLength) then
                      begin
                        if IntegrityLevel = SystemIntegrityLevel then
                          PIntegrityLevel := SYSTEM_INTEGRITY_SID
                        else if IntegrityLevel = HighIntegrityLevel then
                          PIntegrityLevel := HIGH_INTEGRITY_SID
                        else if IntegrityLevel = MediumIntegrityLevel then
                          PIntegrityLevel := MEDIUM_INTEGRITY_SID
                        else if IntegrityLevel = LowIntegrityLevel then
                          PIntegrityLevel := LOW_INTEGRITY_SID;
                        if ConvertStringSidToSidW(PIntegrityLevel, Sid) then
                        begin
                          MandatoryLabel.Label_.Sid := Sid;
                          MandatoryLabel.Label_.Attributes := SE_GROUP_INTEGRITY;
                          if SetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, SizeOf(TOKEN_MANDATORY_LABEL) + GetLengthSid(Sid)) then
                          begin
                            Result := CreateProcessWithTokenW(ImpersonateToken, 0, ApplicationName, CommandLine, CreationFlags, Environment, CurrentDirectory, @StartupInfo, @ProcessInformation);
                            SetLastError(0);
                          end;
                        end;
                      end;
                    finally
                      FreeMem(MandatoryLabel);
                    end;
                  end;
                end;
              finally
                CloseHandle(ImpersonateToken);
              end;
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;

function CreateProcessAsSystemW_XP(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation): Boolean;
var
  ProcessHandle, TokenHandle, TokenHandle2: THandle;
  ImpersonateToken: THandle;
  PSD: PPSECURITY_DESCRIPTOR;
  ppDacl: PACL;
begin
  Result := False;
  try
    ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, GetWinlogonProcessId);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            if GetSecurityInfo(TokenHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, @ppDacl, nil, PSD) = 0 then
            begin
              if SetSecurityInfo(TokenHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, nil, nil) = 0 then
              begin
                try
                  if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle2) then
                  begin
                    try
                      if DuplicateTokenEx(TokenHandle2, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, ImpersonateToken) then
                      begin
                        try
                          if ImpersonateLoggedOnUser(ImpersonateToken) then
                          begin
                            try
                              Result := CreateProcessAsUserW(ImpersonateToken, ApplicationName, CommandLine, nil, nil, False, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation);
                              SetLastError(0);
                            finally
                              RevertToSelf;
                            end;
                          end;
                        finally
                          CloseHandle(ImpersonateToken);
                        end;
                      end;
                    finally
                      CloseHandle(TokenHandle2);
                    end;
                  end;
                finally
                  SetSecurityInfo(TokenHandle, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, ppDacl, nil);
                end;
              end;
              LocalFree(DWORD(ppDacl));
              LocalFree(DWORD(PSD));
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;

function CreateProcessAsSystemW(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel): Boolean;
begin
  Result := False;
  try
    if WindowsVersion >= 60 then
      Result := CreateProcessAsSystemW_Vista(ApplicationName, CommandLine, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation, IntegrityLevel)
    else
      Result := CreateProcessAsSystemW_XP(ApplicationName, CommandLine, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation);
  except
  end;
end;

function CreateProcessAsSystemW(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation): Boolean;
begin
  Result := False;
  try
    if WindowsVersion >= 60 then
      Result := CreateProcessAsSystemW_Vista(ApplicationName, CommandLine, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation, SystemIntegrityLevel)
    else
      Result := CreateProcessAsSystemW_XP(ApplicationName, CommandLine, CreationFlags, Environment, CurrentDirectory, StartupInfo, ProcessInformation);
  except
  end;
end;

function Initialize: Boolean;
var
  LibraryHandle: HMODULE;
begin
  Result := False;
  try
    AdjustCurrentProcessPrivilege('SeDebugPrivilege', True);
    WindowsVersion := GetWindowsVersion;
    LibraryHandle := LoadLibrary('Advapi32.dll');
    if LibraryHandle <> 0 then
    begin
      @ConvertStringSidToSidW := GetProcAddress(LibraryHandle, 'ConvertStringSidToSidW');
      @CreateProcessWithTokenW := GetProcAddress(LibraryHandle, 'CreateProcessWithTokenW');
      @ConvertStringSidToSidA := GetProcAddress(LibraryHandle, 'ConvertStringSidToSidA');
      @GetTokenInformation := GetProcAddress(LibraryHandle, 'GetTokenInformation');
      @SetTokenInformation := GetProcAddress(LibraryHandle, 'SetTokenInformation');
      @CreateProcessAsUserW := GetProcAddress(LibraryHandle, 'CreateProcessAsUserW');
      FreeLibrary(LibraryHandle);
      LibraryHandle := 0;
      Result := True;
    end;
  except
  end;
end;

function DeInitialize: LongBool;
begin

end;

initialization

Initialize;

finalization

DeInitialize;

end.
