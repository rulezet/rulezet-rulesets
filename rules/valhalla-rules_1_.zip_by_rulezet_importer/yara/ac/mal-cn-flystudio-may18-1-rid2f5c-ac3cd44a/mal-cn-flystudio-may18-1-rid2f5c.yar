import "pe"
rule MAL_CN_FlyStudio_May18_1_RID2F5C : CHINA DEMO EXE FILE MAL {
   meta:
      description = "Detects malware / hacktool detected in May 2018"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-11 11:53:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b85147366890598518d4f277d44506eef871fd7fc6050d8f8e68889cae066d9e"
      tags = "CHINA, DEMO, EXE, FILE, MAL"
      required_modules = "pe"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
      $s2 = "www.cfyhack.cn" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 5000KB and ( pe.imphash ( ) == "65ae5cf17140aeaf91e3e9911da0ee3e" or 1 of them )
}