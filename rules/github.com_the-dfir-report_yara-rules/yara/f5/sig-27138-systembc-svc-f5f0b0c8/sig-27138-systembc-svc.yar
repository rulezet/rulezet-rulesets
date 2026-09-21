import "pe"
rule sig_27138_systembc_svc {
   meta:
      description = "27138 - file svc.dll"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "2389b3978887ec1094b26b35e21e9c77826d91f7fa25b2a1cb5ad836ba2d7ec4"
   strings:
      $s1 = "socks64.dll" fullword ascii
      $s2 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" fullword ascii
      $s3 = "FGET %s HTTP/1.0" fullword ascii
      $s4 = "rundll" fullword ascii
      $s5 = "SWVATAUAVAWH" fullword ascii
      $s6 = "SQWVATAUAVAWH" fullword ascii
      $s7 = "PSWVATAUAVAWH" fullword ascii
      $s8 = "XA_A^A]A\\^_[]" fullword ascii
      $s9 = "(A_A^A]A\\^_[]" fullword ascii
      $s10 = "8A_A^A]A\\^_[]" fullword ascii
      $s11 = "A_A^A]A\\^_[X]" fullword ascii
      $s12 = "A_A^A]A\\^_Y[]" fullword ascii
      $s13 = "A_A^A]A\\^_[]" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      ( pe.imphash() == "dbd4201cf48f9c38a17d30012392cf92" and pe.exports("rundll") or 8 of them )
}