rule tools_NTCmd_RID2B57 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file NTCmd.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:02:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "pipecmd \\\\%s -U:%s -P:\"\" %s" fullword ascii
      $s2 = "[Usage]:  %s <HostName|IP> <Username> <Password>" fullword ascii
      $s3 = "pipecmd \\\\%s -U:%s -P:%s %s" fullword ascii
      $s4 = "============By uhhuhy (Feb 18,2003) - http://www.cnhonker.net============" fullword ascii
      $s5 = "=======================NTcmd v0.11 for HScan v1.20=======================" fullword ascii
      $s6 = "NTcmd>" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 80KB and 2 of them
}