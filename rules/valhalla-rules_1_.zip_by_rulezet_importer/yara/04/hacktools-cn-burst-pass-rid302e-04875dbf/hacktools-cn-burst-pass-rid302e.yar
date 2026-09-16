rule Hacktools_CN_Burst_pass_RID302E : CHINA DEMO SUSP {
   meta:
      description = "Disclosed hacktool set - file pass.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-17 12:28:51"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "123456.com" fullword ascii
      $s1 = "123123.com" fullword ascii
      $s2 = "360.com" fullword ascii
      $s3 = "123.com" fullword ascii
      $s4 = "juso.com" fullword ascii
      $s5 = "sina.com" fullword ascii
      $s7 = "changeme" fullword ascii
      $s8 = "master" fullword ascii
      $s9 = "google.com" fullword ascii
      $s10 = "chinanet" fullword ascii
      $s12 = "lionking" fullword ascii
   condition: 
      all of them
}