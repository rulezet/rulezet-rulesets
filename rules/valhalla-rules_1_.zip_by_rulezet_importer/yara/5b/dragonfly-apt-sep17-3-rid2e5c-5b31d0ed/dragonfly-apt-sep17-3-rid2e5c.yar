import "pe"
rule DragonFly_APT_Sep17_3_RID2E5C : APT DEMO EXE FILE G0035 MAL {
   meta:
      description = "Detects malware from DrqgonFly APT report"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
      date = "2017-09-12 11:11:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b051a5997267a5d7fa8316005124f3506574807ab2b25b037086e2e971564291"
      tags = "APT, DEMO, EXE, FILE, G0035, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "kernel64.dll" fullword ascii
      $s2 = "ws2_32.dQH" fullword ascii
      $s3 = "HGFEDCBADCBA" fullword ascii
      $s4 = "AWAVAUATWVSU" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 40KB and ( pe.imphash ( ) == "6f03fb864ff388bac8680ac5303584be" or all of them ) )
}