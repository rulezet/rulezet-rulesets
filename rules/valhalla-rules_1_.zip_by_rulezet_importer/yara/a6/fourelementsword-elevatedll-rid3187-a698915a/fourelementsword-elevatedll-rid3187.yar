rule FourElementSword_ElevateDLL_RID3187 : DEMO EXE FILE MAL {
   meta:
      description = "Detects FourElementSword Malware"
      author = "Florian Roth"
      reference = "not set"
      date = "2016-03-26 13:26:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
      hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Elevate.dll" fullword wide
      $x2 = "ResN32.dll" fullword wide
      $s1 = "Kingsoft\\Antivirus" fullword wide
      $s2 = "KasperskyLab\\protected" fullword wide
      $s3 = "Sophos" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 1 of ( $x* ) and all of ( $s* ) ) or ( all of them )
}