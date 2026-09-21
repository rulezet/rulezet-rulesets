import "pe"
rule sig_24952_cobalt_strike_cscs {
   meta:
      description = "cobalt_strike - file cscs.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "5d1817065266822df9fa6e8c5589534e031bb6a02493007f88d51a9cfb92e89b"
   strings:
      $s1 = "release.exe" fullword wide
      $s2 = "AVAUATUWVH" fullword ascii
      $s3 = "AWAVAUATVSH" fullword ascii
      $s4 = "AVAUATSH" fullword ascii
      $s5 = "0.1.1.1" fullword wide
      $s6 = "@@@@AI@@@@LB@@@@@@@@ODS@@@DWC\\@`@@@@@@@@@@@@@@dfnk@@jF@@DF@@[D@@" fullword ascii
      $s7 = "(LDHP\\DH " fullword ascii
      $s8 = "p\"\"\"\"\"\"\"'wwxwwwwr\"\"\"" fullword ascii
      $s9 = "AWAVAUATH" fullword ascii 
      $s10 = "<PdMqC!" fullword ascii
      $s11 = "^_A\\A]A^" fullword ascii 
      $s12 = "AWAVAUATSH" fullword ascii 
      $s13 = "8[^_A\\A]A^H" fullword ascii 
      $s14 = "[RRRR[[[[w|w" fullword ascii
      $s15 = "!LDHA\\DH" fullword ascii
      $s16 = ".qEf'2" fullword ascii
      $s17 = ".vDf#\"" fullword ascii
      $s18 = "AVAUATWVH" fullword ascii 
      $s19 = "[^_A\\A]A^" fullword ascii 
      $s20 = ".FEfKB9\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "d753703b724a7f61d54c7d098e86ec92" or 12 of them )
}