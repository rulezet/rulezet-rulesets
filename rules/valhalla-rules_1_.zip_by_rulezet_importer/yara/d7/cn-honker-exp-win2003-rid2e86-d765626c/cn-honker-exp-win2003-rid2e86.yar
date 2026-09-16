rule CN_Honker_exp_win2003_RID2E86 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file win2003.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:18:11"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
      $s2 = "The shell \"cmd\" success!" fullword ascii
      $s4 = "Not Windows NT family OS." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}