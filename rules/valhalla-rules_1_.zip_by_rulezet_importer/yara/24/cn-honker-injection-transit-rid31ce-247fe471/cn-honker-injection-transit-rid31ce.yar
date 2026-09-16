rule CN_Honker_Injection_transit_RID31CE : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file Injection_transit.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:38:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "<description>Your app description here</description> " fullword ascii
      $s4 = "Copyright (C) 2003 ZYDSoft Corp." fullword wide
      $s5 = "ScriptnackgBun" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3175KB and all of them
}