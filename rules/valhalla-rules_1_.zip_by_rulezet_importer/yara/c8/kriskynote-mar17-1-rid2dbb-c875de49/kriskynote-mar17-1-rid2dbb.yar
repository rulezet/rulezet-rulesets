rule Kriskynote_Mar17_1_RID2DBB : DEMO EXE FILE MAL {
   meta:
      description = "Detects Kriskynote Malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-03 10:44:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a19c4b615aa54207604b181873e614d84126b639fee2cce3ca9d5bd863f6f577"
      hash2 = "62b41db0bf63fa45a2c2b0f5df8c2209a5d96bf2bddf82749595c66d30b7ec61"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "gzwrite64" fullword ascii
      $opa1 = { e8 6b fd ff ff 83 f8 ff 74 65 83 7b 28 00 74 42 } 
      $opb1 = { 8a 04 08 8b 8e a4 16 00 00 88 44 24 0c 66 c7 04 } 
      $opb2 = { 89 4e 6c 89 46 74 e9 ad fc ff ff 8b 46 68 85 c0 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and $s1 and ( $opa1 or all of ( $opb* ) )
}