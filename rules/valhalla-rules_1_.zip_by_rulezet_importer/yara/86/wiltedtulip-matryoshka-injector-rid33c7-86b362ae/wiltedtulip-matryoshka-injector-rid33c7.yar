import "pe"
rule WiltedTulip_matryoshka_Injector_RID33C7 : APT DEMO EXE FILE {
   meta:
      description = "Detects hack tool used in Operation Wilted Tulip"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/tulip"
      date = "2017-07-23 15:02:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c41e97b3b22a3f0264f10af2e71e3db44e53c6633d0d690ac4d2f8f5005708ed"
      hash2 = "b93b5d6716a4f8eee450d9f374d0294d1800784bc99c6934246570e4baffe509"
      tags = "APT, DEMO, EXE, FILE"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $s1 = "Injector.dll" fullword ascii
      $s2 = "ReflectiveLoader" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them ) or ( pe.exports ( "__dec" ) and pe.exports ( "_check" ) and pe.exports ( "_dec" ) and pe.exports ( "start" ) and pe.exports ( "test" ) )
}