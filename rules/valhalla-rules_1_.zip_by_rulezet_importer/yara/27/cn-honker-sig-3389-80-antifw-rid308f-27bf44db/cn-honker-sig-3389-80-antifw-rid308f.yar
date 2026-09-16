rule CN_Honker_sig_3389_80_AntiFW_RID308F : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file AntiFW.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:45:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Set TS to port:80 Successfully!" fullword ascii
      $s2 = "Now,set TS to port 80" fullword ascii
      $s3 = "echo. >>amethyst.reg" fullword ascii
      $s4 = "del amethyst.reg" fullword ascii
      $s5 = "AntiFW.cpp" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 30KB and 2 of them
}