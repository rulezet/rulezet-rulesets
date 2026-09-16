rule CN_Honker_windows_mstsc_enhanced_RMDSTC_RID361C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file RMDSTC.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 16:41:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "zava zir5@163.com" fullword wide
      $s1 = "By newccc" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them
}