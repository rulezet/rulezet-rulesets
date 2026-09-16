rule CN_Honker_GetWebShell_RID2EFD : CHINA DEMO EXE FILE HKTL T1021_002 T1087_002 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file GetWebShell.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:38:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1021_002, T1087_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "echo P.Open \"GET\",\"http://www.baidu.com/ma.exe\",0 >>run.vbs" fullword ascii
      $s5 = "http://127.0.0.1/sql.asp?id=1" fullword wide
      $s14 = "net user admin$ hack /add" fullword wide
      $s15 = ";Drop table [hack];create table [dbo].[hack] ([cmd] [image])--" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 70KB and 1 of them
}