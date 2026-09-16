import "pe"
rule Sofacy_Trojan_Loader_Feb18_1_RID315E : DEMO EXE FILE G0007 MAL RUSSIA {
   meta:
      description = "Sofacy Activity Feb 2018"
      author = "Florian Roth"
      reference = "https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100"
      date = "2018-03-01 13:19:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "335565711db93cd02d948f472c51598be4d62d60f70f25a20449c07eae36c8c5"
      tags = "DEMO, EXE, FILE, G0007, MAL, RUSSIA"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $x1 = "%appdata%\\nad.dll" fullword wide
      $s3 = "%appdata%\\nad.bat" fullword wide
      $s1 = "apds.dll" fullword ascii
      $s2 = "nad.dll\"" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and ( pe.imphash ( ) == "a2d1be6502b4b3c28959a4fb0196ea45" or pe.exports ( "VidBitRpl" ) or 1 of ( $x* ) or 2 of them )
}