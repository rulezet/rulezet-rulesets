rule HKTL_LNX_Pnscan_RID2C57 : DEMO HKTL LINUX T1046 {
   meta:
      description = "Detects Pnscan port scanner"
      author = "Florian Roth"
      reference = "https://github.com/ptrrkssn/pnscan"
      date = "2019-05-27 09:45:01"
      score = 55
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, LINUX, T1046"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "-R<hex list>   Hex coded response string to look for." fullword ascii
      $x2 = "This program implements a multithreaded TCP port scanner." ascii wide
   condition: 
      filesize < 6000KB and 1 of them
}