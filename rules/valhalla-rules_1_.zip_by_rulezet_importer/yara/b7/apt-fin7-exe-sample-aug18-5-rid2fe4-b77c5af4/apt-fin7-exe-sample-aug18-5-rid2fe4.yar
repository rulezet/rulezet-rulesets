rule APT_FIN7_EXE_Sample_Aug18_5_RID2FE4 : APT DEMO EXE FILE G0046 RUSSIA {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01 12:16:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7789a3d7d05c30b4efaf3f2f5811804daa56d78a9a660968a4f1f9a78a9108a0"
      tags = "APT, DEMO, EXE, FILE, G0046, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "x0=%d, y0=%d, x1=%d, y1=%d" fullword ascii
      $s3 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 400KB and all of them
}