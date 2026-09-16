rule Destructive_Ransomware_Gen1_RID31CB : CRIME DEMO EXE FILE MAL RANSOM {
   meta:
      description = "Detects destructive malware"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/olympic-destroyer.html"
      date = "2018-02-12 13:37:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ae9a4e244a9b3c77d489dee8aeaf35a7c3ba31b210e76d81ef2e91790f052c85"
      tags = "CRIME, DEMO, EXE, FILE, MAL, RANSOM"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "/set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" fullword wide
      $x2 = "delete shadows /all /quiet" fullword wide
      $x3 = "delete catalog -quiet" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them
}