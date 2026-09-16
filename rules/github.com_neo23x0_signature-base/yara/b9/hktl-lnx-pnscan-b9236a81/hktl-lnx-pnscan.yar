rule HKTL_LNX_Pnscan {
   meta:
      description = "Detects Pnscan port scanner"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/ptrrkssn/pnscan"
      date = "2019-05-27"
      score = 55
      id = "46c6c0d9-08bb-5de3-ad14-c1a7ab0542c6"
   strings:
      $x1 = "-R<hex list>   Hex coded response string to look for." fullword ascii
      $x2 = "This program implements a multithreaded TCP port scanner." ascii wide
   condition:
      filesize < 6000KB and 1 of them
}