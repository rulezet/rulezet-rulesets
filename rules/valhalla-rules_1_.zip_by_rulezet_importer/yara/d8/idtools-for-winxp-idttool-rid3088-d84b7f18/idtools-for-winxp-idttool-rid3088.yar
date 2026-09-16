rule IDTools_For_WinXP_IdtTool_RID3088 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file IdtTool.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 12:43:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "IdtTool.sys" fullword ascii
      $s4 = "Idt Tool bY tMd[CsP]" fullword wide
      $s6 = "\\\\.\\slIdtTool" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 25KB and all of them
}