rule IDTools_For_WinXP_IdtTool_2_RID3119 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file IdtTool.sys"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:08:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Device\\devIdtTool" wide
      $s1 = "IoDeleteSymbolicLink" fullword ascii
      $s3 = "IoDeleteDevice" fullword ascii
      $s6 = "IoCreateSymbolicLink" fullword ascii
      $s7 = "IoCreateDevice" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 7KB and all of them
}