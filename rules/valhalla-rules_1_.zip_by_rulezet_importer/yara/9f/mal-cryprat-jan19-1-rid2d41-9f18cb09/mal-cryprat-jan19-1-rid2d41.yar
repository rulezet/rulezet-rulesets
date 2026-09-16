import "pe"
rule MAL_CrypRAT_Jan19_1_RID2D41 : DEMO EXE FILE MAL {
   meta:
      description = "Detects CrypRAT"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-01-07 10:24:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Cryp_RAT" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and ( pe.imphash ( ) == "2524e5e9fe04d7bfe5efb3a5e400fe4b" or 1 of them )
}