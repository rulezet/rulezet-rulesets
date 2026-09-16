rule HKTL_CGISscan_CGIScan_RID2E25 : DEMO HKTL {
   meta:
      description = "Semiautomatically generated YARA rule on file CGIScan.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 11:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Wang Products" fullword wide
      $s2 = "WSocketResolveHost: Cannot convert host address '%s'" 
      $s3 = "tcp is the only protocol supported thru socks server" 
   condition: 
      all of ( $s* )
}