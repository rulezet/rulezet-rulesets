rule GoodToolset_ms11011_RID2DB7 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file ms11011.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:43:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\i386\\Hello.pdb" ascii
      $s1 = "OS not supported." fullword ascii
      $s3 = "Not supported." fullword wide
      $s4 = "SystemDefaultEUDCFont" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}