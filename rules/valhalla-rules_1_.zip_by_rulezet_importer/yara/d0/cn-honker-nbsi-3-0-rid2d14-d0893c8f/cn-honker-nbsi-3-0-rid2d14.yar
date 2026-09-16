rule CN_Honker_NBSI_3_0_RID2D14 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file NBSI 3.0.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:16:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide
      $s2 = "http://localhost/1.asp?id=16" fullword ascii
      $s3 = " exec master.dbo.xp_cmdshell @Z--" fullword wide
      $s4 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2600KB and 2 of them
}