rule Foudre_Backdoor_1_RID2D8A : DEMO EXE FILE MAL {
   meta:
      description = "Detects Foudre Backdoor"
      author = "Florian Roth"
      reference = "https://www.paloaltonetworks.com/blog/2017/08/unit42-prince-persia-ride-lightning-infy-returns-foudre/"
      date = "2017-08-01 10:36:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "7e73a727dc8f3c48e58468c3fd0a193a027d085f25fa274a6e187cf503f01f74"
      hash2 = "7ce2c5111e3560aa6036f98b48ceafe83aa1ac3d3b33392835316c859970f8bc"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "initialization failed: Reinstall the program" fullword wide
      $s2 = "SnailDriver V1" fullword wide
      $s3 = "lp.ini" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 2 of them )
}