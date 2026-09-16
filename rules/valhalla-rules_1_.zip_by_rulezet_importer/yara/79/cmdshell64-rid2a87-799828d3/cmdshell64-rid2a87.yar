rule CmdShell64_RID2A87 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file CmdShell64_RID2A87.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 06:36:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
      $s2 = "ServiceCmdShell" fullword ascii
      $s3 = "<!-- If your application is designed to work with Windows 8.1, uncomment the fol" ascii
      $s4 = "ServiceSystemShell" fullword wide
      $s5 = "[Root@CmdShell ~]#" fullword wide
      $s6 = "Hello Man 2015 !" fullword wide
      $s7 = "CmdShell" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 30KB and 4 of them
}