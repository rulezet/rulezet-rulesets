rule Xtreme_Sep17_2_RID2C06 : DEMO EXE FILE MAL {
   meta:
      description = "Detects XTREME sample analyzed in September 2017"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-27 09:31:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f8413827c52a5b073bdff657d6a277fdbfda29d909b4247982f6973424fa2dcc"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Spy24.exe" fullword wide
      $s2 = "Remote Service Application" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them )
}