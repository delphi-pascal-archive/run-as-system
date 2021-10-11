object Form1: TForm1
  Left = 217
  Top = 128
  BorderIcons = [biSystemMenu, biMinimize]
  BorderStyle = bsSingle
  Caption = 'Run as System'
  ClientHeight = 73
  ClientWidth = 425
  Color = clBtnFace
  Font.Charset = RUSSIAN_CHARSET
  Font.Color = clWindowText
  Font.Height = -13
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poDesktopCenter
  OnCreate = FormCreate
  PixelsPerInch = 120
  TextHeight = 16
  object Button1: TButton
    Left = 8
    Top = 40
    Width = 409
    Height = 25
    Caption = 'Run application as System'
    TabOrder = 1
    OnClick = Button1Click
  end
  object Edit1: TEdit
    Left = 8
    Top = 8
    Width = 297
    Height = 25
    TabOrder = 0
  end
  object Button2: TButton
    Left = 312
    Top = 8
    Width = 105
    Height = 25
    Caption = 'Browse...'
    TabOrder = 2
    OnClick = Button2Click
  end
  object OpenDialog1: TOpenDialog
    Left = 80
    Top = 28
  end
end
