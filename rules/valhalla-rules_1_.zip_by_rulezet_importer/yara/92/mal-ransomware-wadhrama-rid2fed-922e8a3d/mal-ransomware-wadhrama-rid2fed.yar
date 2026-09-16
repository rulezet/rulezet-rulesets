import "pe"
rule MAL_Ransomware_Wadhrama_RID2FED : CRIME DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects Wadhrama Ransomware via Imphash"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-04-07 12:18:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "557c68e38dce7ea10622763c10a1b9f853c236b3291cd4f9b32723e8714e5576"
      tags = "CRIME, DEMO, EXE, FILE, MAL, RANSOM"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and pe.imphash ( ) == "f86dec4a80961955a89e7ed62046cc0e"
}