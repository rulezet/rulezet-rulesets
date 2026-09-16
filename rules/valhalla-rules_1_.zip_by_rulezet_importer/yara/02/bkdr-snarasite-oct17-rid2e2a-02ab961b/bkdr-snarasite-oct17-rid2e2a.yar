import "pe"
rule BKDR_Snarasite_Oct17_RID2E2A : DEMO EXE FILE MAL {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-10-07 11:02:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "36ba92cba23971ca9d16a0b4f45c853fd5b3108076464d5f2027b0f56054fd62"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and ( pe.imphash ( ) == "322bef04e1e1ac48875036e38fb5c23c" or pe.imphash ( ) == "15088754757513c92fa36ba5590e907b" )
}