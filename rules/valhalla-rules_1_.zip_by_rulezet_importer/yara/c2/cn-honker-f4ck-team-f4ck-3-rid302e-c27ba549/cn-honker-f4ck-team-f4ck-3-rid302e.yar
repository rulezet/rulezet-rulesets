rule CN_Honker_F4ck_Team_F4ck_3_RID302E : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file F4ck_3.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:28:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "F4ck.exe" fullword wide
      $s2 = "@Netapi32.dll" fullword ascii
      $s3 = "Team.F4ck.Net" fullword wide
      $s6 = "NO Net Add User" fullword wide
      $s7 = "DLL ERROR" fullword ascii
      $s11 = "F4ck Team" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 3 of them
}