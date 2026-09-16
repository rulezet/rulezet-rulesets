rule APT_FIN7_EXE_Sample_Aug18_7_RID2FE6 : APT DEMO EXE FILE G0046 RUSSIA {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01 12:16:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ce8ce35f85406cd7241c6cc402431445fa1b5a55c548cca2ea30eeb4a423b6f0"
      tags = "APT, DEMO, EXE, FILE, G0046, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "libpng version" fullword ascii
      $s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 800KB and all of them
}