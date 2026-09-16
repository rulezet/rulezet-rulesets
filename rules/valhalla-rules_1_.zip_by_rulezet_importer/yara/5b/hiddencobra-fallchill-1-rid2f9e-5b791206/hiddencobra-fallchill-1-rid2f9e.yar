import "pe"
rule HiddenCobra_FallChill_1_RID2F9E : APT DEMO EXE FILE G0032 NK T1218_010 fallchill {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
      date = "2017-11-15 12:04:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "a606716355035d4a1ea0b15f3bee30aad41a2c32df28c2d468eafd18361d60d6"
      tags = "APT, DEMO, EXE, FILE, G0032, NK, T1218_010, fallchill"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "REGSVR32.EXE.MUI" fullword wide
      $s2 = "Microsoft Corporation. All rights reserved." fullword wide
      $s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide
      $s4 = "\" goto Loop" fullword ascii
      $e1 = "xolhvhlxpvg" fullword ascii
      $e2 = "tvgslhgybmanv" fullword ascii
      $e3 = "CivagvTllosvok32Smakhslg" fullword ascii
      $e4 = "GvgCfiivmgDrivxglibW" fullword ascii
      $e5 = "OkvmPilxvhhTlpvm" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "6135d9bc3591ae7bc72d070eadd31755" or 3 of ( $s* ) or 4 of them )
}