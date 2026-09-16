rule CN_Honker_GetHashes_RID2E43 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:07:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "SAM\\Domains\\Account\\Users\\Names registry hive reading error!" fullword ascii
      $s1 = "GetHashes <SAM registry file> [System key file]" fullword ascii
      $s2 = "Note: Windows registry file shall begin from 'regf' signature!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 87KB and 2 of them
}