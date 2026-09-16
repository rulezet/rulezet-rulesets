import "pe"
rule MAL_Ramnit_May19_1_RID2D35 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Ramnit malware"
      author = "Florian Roth"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31 10:22:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d7ec3fcd80b3961e5bab97015c91c843803bb915c13a4a35dfb5e9bdf556c6d3"
      tags = "DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and pe.imphash ( ) == "500cd02578808f964519eb2c85153046"
}