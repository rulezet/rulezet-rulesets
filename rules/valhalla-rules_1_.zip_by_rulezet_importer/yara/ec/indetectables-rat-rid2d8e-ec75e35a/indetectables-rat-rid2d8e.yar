rule Indetectables_RAT_RID2D8E : DEMO EXE FILE MAL {
   meta:
      description = "Detects Indetectables RAT based on strings found in research by Paul Rascagneres & Ronan Mouchoux"
      author = "Florian Roth"
      reference = "http://www.sekoia.fr/blog/when-a-brazilian-string-smells-bad/"
      date = "2015-10-01 10:36:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "081905074c19d5e32fd41a24b4c512d8fd9d2c3a8b7382009e3ab920728c7105"
      hash2 = "66306c2a55a3c17b350afaba76db7e91bfc835c0e90a42aa4cf59e4179b80229"
      hash3 = "1fa810018f6dd169e46a62a4f77ae076f93a853bfc33c7cf96266772535f6801"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Coded By M3" fullword wide
      $s2 = "Stub Undetector M3" fullword wide
      $s3 = "www.webmenegatti.com.br" wide
      $s4 = "M3n3gatt1" fullword wide
      $s5 = "TheMisterFUD" fullword wide
      $s6 = "KillZoneKillZoneKill" fullword ascii
      $s7 = "[[__M3_F_U_D_M3__]]$" fullword ascii
      $s8 = "M3_F_U_D_M3" ascii
      $s9 = "M3n3gatt1hack3r" fullword wide
      $s10 = "M3n3gatt1hack3r" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and 1 of them
}