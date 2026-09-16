rule MAL_Etoroloro_Malicious_NodePackage_Dec25_RID3677 : DEMO EXE FILE MAL {
   meta:
      description = "Detects malicious component of node package named Etoroloro"
      author = "Pezier Pierre-Henri"
      reference = "Internal Research"
      date = "2025-12-12 16:57:01"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "DLLSideload." 
      $s2 = "Failed to expand path:" wide
      $op1 = { 41 0f af c0 48 8d 52 01 0f b6 c9 45 69 c0 35 d4 04 00 03 c1 0f b6 0a 84 c9 75 e5 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( all of ( $s* ) or $op1 )
}