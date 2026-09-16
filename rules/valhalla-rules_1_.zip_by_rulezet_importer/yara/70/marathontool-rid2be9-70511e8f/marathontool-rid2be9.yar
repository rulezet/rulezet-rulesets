rule MarathonTool_RID2BE9 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file MarathonTool_RID2BE9.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:26:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "MarathonTool_RID2BE9" ascii
      $s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
      $s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1040KB and all of them
}