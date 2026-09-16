rule APT_FIN7_EXE_Sample_Aug18_2_RID2FE1 : APT DEMO EXE FILE G0046 RUSSIA {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01 12:16:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "60cd98fc4cb2ae474e9eab81cd34fd3c3f638ad77e4f5d5c82ca46f3471c3020"
      tags = "APT, DEMO, EXE, FILE, G0046, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "constructor or from DllMain." fullword ascii
      $s2 = "Network Software Ltd0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them
}