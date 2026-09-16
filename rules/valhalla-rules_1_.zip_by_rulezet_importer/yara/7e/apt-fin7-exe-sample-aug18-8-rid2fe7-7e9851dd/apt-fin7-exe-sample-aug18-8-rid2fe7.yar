rule APT_FIN7_EXE_Sample_Aug18_8_RID2FE7 : APT DEMO EXE FILE G0046 RUSSIA {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01 12:17:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d8bda53d7f2f1e4e442a0e1c30a20d6b0ac9c6880947f5dd36f78e4378b20c5c"
      tags = "APT, DEMO, EXE, FILE, G0046, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "GetL3st3rr" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 600KB and all of them
}