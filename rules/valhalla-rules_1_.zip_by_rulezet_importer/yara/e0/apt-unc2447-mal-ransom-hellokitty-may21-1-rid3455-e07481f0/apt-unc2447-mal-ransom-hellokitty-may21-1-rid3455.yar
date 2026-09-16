rule APT_UNC2447_MAL_RANSOM_HelloKitty_May21_1_RID3455 : APT CRIME DEMO EXE MAL RANSOM T1047 {
   meta:
      description = "Detects HelloKitty Ransomware samples from UNC2447 campaign"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2021/04/unc2447-sombrat-and-fivehands-ransomware-sophisticated-financial-threat.html"
      date = "2021-05-01 15:26:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "02a08b994265901a649f1bcf6772bc06df2eb51eb09906af9fd0f4a8103e9851"
      hash2 = "0e5f7737704c8f25b2b8157561be54a463057cd4d79c7e016c30a1cf6590a85c"
      hash3 = "52dace403e8f9b4f7ea20c0c3565fa11b6953b404a7d49d63af237a57b36fd2a"
      tags = "APT, CRIME, DEMO, EXE, MAL, RANSOM, T1047"
      minimum_yara = "3.5.0"
      
   strings:
      $xop1 = { 8b 45 08 8b 75 f4 fe 85 f7 fd ff ff 0f 11 44 05 b4 83 c0 10 89 45 08 83 f8 30 7c 82 } 
      $xop2 = { 81 c3 dc a9 b0 5c c1 c9 0b 33 c8 89 55 a0 8b c7 8b 7d e0 c1 c8 06 33 f7 } 
      $s1 = "select * from Win32_ShadowCopy" wide fullword
      $s2 = "bootfont.bin" wide fullword
      $s3 = "DECRYPT_NOTE.txt" wide fullword
      $s4 = ".onion" wide
      $sop1 = { 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 0f 11 45 ec } 
      $sop2 = { 56 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 } 
      $sop3 = { 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and 1 of ( $x* ) or 3 of them
}