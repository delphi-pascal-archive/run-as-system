object Form1: TForm1
  Left = 416
  Top = 302
  BorderIcons = [biSystemMenu]
  BorderStyle = bsSingle
  Caption = 'Run As System'
  ClientHeight = 153
  ClientWidth = 620
  Color = clBtnFace
  Font.Charset = RUSSIAN_CHARSET
  Font.Color = clBlack
  Font.Height = -11
  Font.Name = 'Microsoft Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poDesktopCenter
  OnCreate = FormCreate
  DesignSize = (
    620
    153)
  PixelsPerInch = 96
  TextHeight = 13
  object Button1: TButton
    Left = 21
    Top = 102
    Width = 118
    Height = 25
    Caption = 'Run As System'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Edit1: TEdit
    Left = 21
    Top = 30
    Width = 549
    Height = 21
    Anchors = [akLeft, akTop, akRight]
    TabOrder = 1
    Text = 'C:\WINDOWS\system32\calc.exe'
  end
  object Button2: TButton
    Left = 575
    Top = 29
    Width = 23
    Height = 23
    Anchors = [akTop, akRight]
    Caption = '...'
    TabOrder = 2
    OnClick = Button2Click
  end
  object ComboBox1: TComboBox
    Left = 21
    Top = 57
    Width = 211
    Height = 21
    Style = csDropDownList
    Enabled = False
    ItemHeight = 13
    ItemIndex = 3
    TabOrder = 3
    Text = 'System Integrity Level'
    Items.Strings = (
      'Low Integrity Level'
      'Medium Integrity Level'
      'High Integrity Level'
      'System Integrity Level')
  end
  object OpenDialog1: TOpenDialog
    Left = 300
    Top = 69
  end
  object XPManifest1: TXPManifest
    Left = 336
    Top = 69
  end
end
