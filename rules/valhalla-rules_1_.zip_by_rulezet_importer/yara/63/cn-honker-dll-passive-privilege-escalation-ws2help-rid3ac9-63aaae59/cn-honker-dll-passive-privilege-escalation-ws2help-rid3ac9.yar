rule CN_Honker_DLL_passive_privilege_escalation_ws2help_RID3AC9 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file ws2help.dll"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 20:01:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "PassMinDll.dll" fullword ascii
      $s1 = "\\ws2help.dll" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 30KB and all of them
}