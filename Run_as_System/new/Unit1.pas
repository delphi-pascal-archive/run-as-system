unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, RunAsSystem, StdCtrls, XPMan;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Edit1: TEdit;
    Button2: TButton;
    OpenDialog1: TOpenDialog;
    XPManifest1: TXPManifest;
    ComboBox1: TComboBox;
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

procedure TForm1.Button1Click(Sender: TObject);
var
  StartupInfo: TStartupInfoW;
  ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel;
begin
  case ComboBox1.ItemIndex of
    0: IntegrityLevel:= LowIntegrityLevel;
    1: IntegrityLevel:= MediumIntegrityLevel;
    2: IntegrityLevel:= HighIntegrityLevel;
    3: IntegrityLevel:= SystemIntegrityLevel;
  end;

  ZeroMemory(@StartupInfo, SizeOf(TStartupInfoW));
  FillChar(StartupInfo, SizeOf(TStartupInfoW), 0);
  StartupInfo.cb := SizeOf(TStartupInfoW);
  StartupInfo.lpDesktop := 'WinSta0\Default';
  if CreateProcessAsSystemW(
    PWideChar(WideString(Edit1.Text)),
    PWideChar(WideString(Edit1.Text + ' -read me and do something')),
    NORMAL_PRIORITY_CLASS,
    nil,
    nil,
    StartupInfo,
    ProcessInformation,
    IntegrityLevel) then
  begin
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
  end;
end;

procedure TForm1.Button2Click(Sender: TObject);
begin
  if OpenDialog1.Execute then
    Edit1.Text := OpenDialog1.FileName;
end;

procedure TForm1.FormCreate(Sender: TObject);
begin
  if WindowsVersion >= 60 then
    ComboBox1.Enabled:= True;
end;

end.
