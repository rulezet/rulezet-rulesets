rule APT_UNC2447_MAL_RANSOM_HelloKitty_May21_2_RID3456 : APT CRIME DEMO EXE MAL RANSOM {
   meta:
      description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
      date = "2021-05-01 15:26:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "10887d13dba1f83ef34e047455a04416d25a83079a7f3798ce3483e0526e3768"
      hash2 = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
      hash3 = "501487b025f25ddf1ca32deb57a2b4db43ccf6635c1edc74b9cff54ce0e5bcfe"
      tags = "APT, CRIME, DEMO, EXE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $xop1 = { 50 8d 45 f8 50 ff 75 fc ff 15 ?? ?? 42 00 3d ea 00 00 00 75 18 83 7d f8 00 } 
      $s1 = "HelloKittyMutex" wide
      $s2 = "%s\\read_me_lkd.txt" wide fullword
      $s3 = "/C ping 127.0.0.1 & del %s" wide fullword
      $s4 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
      $sop1 = { 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc ff 15 ?? ?? 42 00 } 
      $sop2 = { 74 12 6a 00 6a 01 ff 75 fc ff 15 ?? ?? 42 00 85 c0 0f 94 c3 ff 75 fc } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and 1 of ( $x* ) or 2 of them
}