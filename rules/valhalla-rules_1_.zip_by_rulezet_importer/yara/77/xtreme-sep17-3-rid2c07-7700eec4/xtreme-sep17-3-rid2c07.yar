rule Xtreme_Sep17_3_RID2C07 : DEMO EXE FILE MAL {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-27 09:31:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f540a4cac716438da0c1c7b31661abf35136ea69b963e8f16846b96f8fd63dde"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Keylogg" fullword ascii
      $s4 = "XTREME" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 700KB and all of them )
}