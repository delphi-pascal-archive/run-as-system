unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, AccCtrl, AclAPI;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Edit1: TEdit;
    Button2: TButton;
    OpenDialog1: TOpenDialog;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function GetOSVersion: Cardinal;
var
  OSVersionInfo: TOSVersionInfo;
begin
  Result:= 0;
  FillChar(OSVersionInfo, Sizeof(OSVersionInfo), 0);
  OSVersionInfo.dwOSVersionInfoSize:= SizeOf(OSVersionInfo);
  if GetVersionEx(OSVersionInfo) then
  begin
    if OSVersionInfo.dwPlatformId = VER_PLATFORM_WIN32_NT then
    begin
      if OSVersionInfo.dwMajorVersion = 5 then
      begin
        if OSVersionInfo.dwMinorVersion = 0 then
          Result:= 50
        else if OSVersionInfo.dwMinorVersion = 2 then
          Result:= 52
        else if OSVersionInfo.dwMinorVersion = 1 then
          Result:= 51
      end;
      if OSVersionInfo.dwMajorVersion = 6 then
      begin
        if OSVersionInfo.dwMinorVersion = 0 then
          Result:= 60
        else if OSVersionInfo.dwMinorVersion = 1 then
          Result:= 61;
      end;
    end;
  end;
end;

function RunAsSystem(ApplicationName: String): Boolean;
var
  lpStartupInfo: TStartupInfo;
  lpProcessInformation: TProcessInformation;
  ppSecurityDescriptor: PPSecurity_Descriptor;
  ppDacl: PACL;
  hProcess, hToken: Cardinal;
begin
  Result:= False;
  if (GetOSVersion > 50) and (GetOSVersion < 60) then
    hProcess:= OpenProcess(PROCESS_QUERY_INFORMATION, False, 4)
  else
    hProcess:= OpenProcess(PROCESS_QUERY_INFORMATION, False, 8);
  if hProcess <> 0 then
  begin
    try
      OpenProcessToken(hProcess, MAXIMUM_ALLOWED, hToken);
      if hToken <> 0 then
      begin
        if GetSecurityInfo(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, @ppDacl, nil, ppSecurityDescriptor) = ERROR_SUCCESS then
        begin
          if SetSecurityInfo(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, nil, nil) = ERROR_SUCCESS then
          begin
            CloseHandle(hToken);
            OpenProcessToken(hProcess, MAXIMUM_ALLOWED, hToken);
            if hToken <> 0 then
            begin
              try
                if ImpersonateLoggedOnUser(hToken) then
                begin
                  ZeroMemory(@lpStartupInfo, SizeOf(lpStartupInfo));
                  lpStartupInfo.cb:= SizeOf(lpStartupInfo);
                  if CreateProcessAsUser(hToken, PChar(ApplicationName), '', nil, nil, False, CREATE_DEFAULT_ERROR_MODE, nil, nil, lpStartupInfo, lpProcessInformation) then
                    Result:= True;
                  RevertToSelf;
                end;
                SetSecurityInfo(hToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nil, nil, ppDacl, nil);
              finally
                CloseHandle(hToken);
              end;
            end;
          end;
        end;
      end;
    finally
      CloseHandle(hProcess);
    end;
  end;
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
  RunAsSystem(Edit1.Text);
end;

procedure TForm1.Button2Click(Sender: TObject);
begin
  if OpenDialog1.Execute then
   Edit1.Text:= OpenDialog1.FileName;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  Edit1.Text:= Application.ExeName;
end;

end.

