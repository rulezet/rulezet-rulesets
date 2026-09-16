rule APT_MAL_NK_Lazarus_VHD_Ransomware_Oct20_2_RID359F : APT CRIME DEMO EXE FILE G0032 MAL NK RANSOM {
   meta:
      description = "Detects Lazarus VHD Ransomware"
      author = "Florian Roth"
      reference = "https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/"
      date = "2020-10-05 16:21:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "097ca829e051a4877bca093cee340180ff5f13a9c266ad4141b0be82aae1a39b"
      hash2 = "73a10be31832c9f1cbbd798590411009da0881592a90feb472e80025dfb0ea79"
      tags = "APT, CRIME, DEMO, EXE, FILE, G0032, MAL, NK, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $op1 = { f9 36 88 08 8d ad fc ff ff ff 66 ff c1 e9 72 86 } 
      $op2 = { c6 c4 58 0f a4 c8 12 8d ad ff ff ff ff 0f b6 44 } 
      $op3 = { 88 02 66 c1 f0 54 8d bf fc ff ff ff 0f ba e0 19 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 9000KB and all of them
}