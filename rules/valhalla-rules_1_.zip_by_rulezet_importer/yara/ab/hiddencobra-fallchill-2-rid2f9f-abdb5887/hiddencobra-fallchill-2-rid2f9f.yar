import "pe"
rule HiddenCobra_FallChill_2_RID2F9F : APT DEMO EXE FILE G0032 NK fallchill {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
      date = "2017-11-15 12:05:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0a118eb23399000d148186b9079fa59caf4c3faa7e7a8f91533e467ac9b6ff41"
      tags = "APT, DEMO, EXE, FILE, G0032, NK, fallchill"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s\\%s.dll" fullword wide
      $s2 = "yurdkr.dll" fullword ascii
      $s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 500KB and ( pe.imphash ( ) == "cb36dcb9909e29a38c387b8a87e7e4ed" or ( 2 of them ) )
}