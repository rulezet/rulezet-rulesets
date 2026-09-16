rule CN_Honker_GetSyskey_RID2E6F : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file GetSyskey.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:14:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "GetSyskey <SYSTEM registry file> [Output system key file]" fullword ascii
      $s4 = "The system key file \"%s\" is created." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them
}