rule CN_Honker_clearlogs_RID2E83 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file clearlogs.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:17:41"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-20"
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "- http://ntsecurity.nu/toolbox/clearlogs/" ascii
      $s4 = "Error: Unable to clear log - " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 140KB and all of them
}