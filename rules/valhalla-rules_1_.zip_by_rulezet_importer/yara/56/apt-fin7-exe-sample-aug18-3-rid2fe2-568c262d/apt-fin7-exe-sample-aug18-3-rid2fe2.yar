rule APT_FIN7_EXE_Sample_Aug18_3_RID2FE2 : APT DEMO EXE FILE G0046 RUSSIA {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01 12:16:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "995b90281774798a376db67f906a126257d314efc21b03768941f2f819cf61a6"
      tags = "APT, DEMO, EXE, FILE, G0046, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "cvzdfhtjkdhbfszngjdng" fullword ascii
      $s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 50KB and 1 of them
}