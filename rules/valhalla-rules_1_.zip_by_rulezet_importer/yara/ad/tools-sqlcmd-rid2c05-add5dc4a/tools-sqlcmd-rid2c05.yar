rule tools_Sqlcmd_RID2C05 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Sqlcmd.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:31:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
      $s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii
      $s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
      $s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
      $s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
      $s10 = "Error,exit!" fullword ascii
      $s11 = "Sqlcmd>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and 3 of them
}