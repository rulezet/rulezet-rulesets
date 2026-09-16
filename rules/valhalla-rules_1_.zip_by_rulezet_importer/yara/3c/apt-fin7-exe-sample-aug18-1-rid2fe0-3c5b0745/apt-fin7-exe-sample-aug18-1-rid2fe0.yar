rule APT_FIN7_EXE_Sample_Aug18_1_RID2FE0 : APT DEMO EXE FILE G0046 RUSSIA {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01 12:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7f16cbe7aa1fbc5b8a95f9d123f45b7e3da144cb88db6e1da3eca38cf88660cb"
      tags = "APT, DEMO, EXE, FILE, G0046, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Manche Enterprises Limited0" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and 1 of them
}