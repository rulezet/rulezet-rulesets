import "pe"
rule Elise_Jan18_1_RID2B74 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Elise malware samples - fake Norton Security NavShExt.dll"
      author = "Florian Roth"
      reference = "https://twitter.com/blu3_team/status/955971742329135105"
      date = "2018-01-24 09:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6dc2a49d58dc568944fef8285ad7a03b772b9bdf1fe4bddff3f1ade3862eae79"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "NavShExt.dll" fullword wide
      $s2 = "Norton Security" fullword wide
      $a1 = "donotbotherme" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 250KB and ( pe.imphash ( ) == "e9478ee4ebf085d1f14f64ba96ef082f" or ( 1 of ( $s* ) and $a1 ) )
}