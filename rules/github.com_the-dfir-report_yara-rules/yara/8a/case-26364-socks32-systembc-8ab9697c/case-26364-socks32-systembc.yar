import "pe"
rule case_26364_socks32_systembc {
   meta:
      description = "Case 26364 - file socks32.exe SystemBC executable"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/08/26/blacksuit-ransomware/"
      date = "2024-08-20"
      hash1 = "9493b512d7d15510ebee5b300c55b67f9f2ff1dda64bddc99ba8ba5024113300"
   strings:
      $x1 = "powershell.exe -windowstyle hidden -Command \"& '%s'\"" fullword ascii
      $s2 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" fullword ascii
      $s3 = "FGET %s HTTP/1.0" fullword ascii
      $s4 = "HOST1:137.220.61.94" fullword ascii
      $s5 = "HOST2:137.220.61.94" fullword ascii
      $s6 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" fullword ascii
      $s7 = "randomdata" fullword ascii
      $s8 = "PORT1:4001" fullword ascii
      $s9 = "GNPj2ht@@" fullword ascii
      $s10 = "PSQRWVh" fullword ascii
      $s11 = "7*80868<8B8H8N8T8Z8`8f8l8r8x8~8" fullword ascii 
      $s12 = "9 9&9,92989>9D9J9P9V9\\9b9h9n9" fullword ascii 
      $s13 = "Pj2ht@@" fullword ascii
      $s14 = "SQRWVi" fullword ascii
      $s15 = "Wj2ht@@" fullword ascii
      $s16 = "j2ht@@" fullword ascii
      $s17 = "w^_ZY[X" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and
      ( pe.imphash() == "d66000edfed0a9938162b2b453ffa516" or ( 1 of ($x*) or 4 of them ) )
}