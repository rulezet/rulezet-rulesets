import "pe"
rule Turla_KazuarRAT_RID2CCD : DEMO EXE FILE G0010 MAL RUSSIA {
   meta:
      description = "Detects Turla Kazuar RAT described by DrunkBinary"
      author = "Markus Neis"
      reference = "https://twitter.com/DrunkBinary/status/982969891975319553"
      date = "2018-04-08 10:04:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6b5d9fca6f49a044fd94c816e258bf50b1e90305d7dab2e0480349e80ed2a0fa"
      hash2 = "743b3347dc86b4a4aa6510648076eeca9eec0ff23c1294b3931263c990bcb5e6"
      tags = "DEMO, EXE, FILE, G0010, MAL, RUSSIA"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "~1.EXE" wide
      $s2 = "dl32.dll" fullword ascii
      $s3 = "HookProc@" ascii
      $s4 = "0`.wtf" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 20KB and ( pe.imphash ( ) == "682156c4380c216ff8cb766a2f2e8817" or 2 of them )
}