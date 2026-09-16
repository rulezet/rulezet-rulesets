rule XScanLib_RID2A05 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file XScanLib_RID2A05.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 03:00:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "XScanLib_RID2A05.dll" fullword ascii
      $s6 = "Ports/%s/%d" fullword ascii
      $s8 = "DEFAULT-TCP-PORT" fullword ascii
      $s9 = "PlugCheckTcpPort" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 360KB and all of them
}