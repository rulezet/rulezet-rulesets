rule Cmdshell32_RID2AA2 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file Cmdshell32_RID2AA2.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 07:21:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cmdshell.exe" fullword wide
      $s2 = "cmdshell" fullword ascii
      $s3 = "[Root@CmdShell ~]#" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 62KB and all of them
}