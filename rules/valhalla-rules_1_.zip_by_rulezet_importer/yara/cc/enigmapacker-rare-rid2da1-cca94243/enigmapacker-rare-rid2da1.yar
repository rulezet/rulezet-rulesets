rule EnigmaPacker_Rare_RID2DA1 : DEMO EXE FILE MAL T1027_002 {
   meta:
      description = "Detects an ENIGMA packed executable"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-04-27 10:40:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "77be6e80a4cfecaf50d94ee35ddc786ba1374f9fe50546f1a3382883cb14cec9"
      tags = "DEMO, EXE, FILE, MAL, T1027_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "P.rel$oc$" fullword ascii
      $s2 = "ENIGMA" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 4000KB and all of them )
}