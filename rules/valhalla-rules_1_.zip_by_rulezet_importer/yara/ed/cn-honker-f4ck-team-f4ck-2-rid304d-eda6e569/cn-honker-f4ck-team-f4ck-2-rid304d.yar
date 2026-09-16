rule CN_Honker_F4ck_Team_f4ck_2_RID304D : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file f4ck_2.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 12:34:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "F4ck.exe" fullword wide
      $s2 = "@Netapi32.dll" fullword ascii
      $s3 = "Team.F4ck.Net" fullword wide
      $s8 = "Administrators" fullword ascii
      $s9 = "F4ck Team" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 220KB and 2 of them
}