import "pe"
rule sig_27138_lockbit_sd {
   meta:
      description = "27138 - file sd.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2025/01/27/cobalt-strike-and-a-pair-of-socks-lead-to-lockbit-ransomware/"
      date = "2025-01-23"
      hash1 = "c1173628f18f7430d792bbbefc6878bced4539c8080d518555d08683a3f1a835"
   strings:
      $s1 = "< /s|V" fullword ascii
      $s2 = "7- h^O" fullword ascii
      $s3 = "NBWg|?G" fullword ascii
      $s4 = "}xcVW*&%%" fullword ascii
      $s5 = "joCw}sP" fullword ascii
      $s6 = "oVHpT0S" fullword ascii
      $s7 = "ngMVj;#<d" fullword ascii
      $s8 = "PNaWt'." fullword ascii
      $s9 = "JMBQWb=\\" fullword ascii
      $s10 = "37TsYA?" fullword ascii
      $s11 = "mSLYP&`d" fullword ascii
      $s12 = "UkqZ3mg" fullword ascii
      $s13 = "jQeP]q-W" fullword ascii
      $s14 = "ikhN=Z\\f" fullword ascii
      $s15 = "MOnt`#$z" fullword ascii
      $s16 = "qtkw[,4" fullword ascii
      $s17 = "rKc4[yNent+#" fullword ascii
      $s18 = "GuiA3\"" fullword ascii
      $s19 = "kAJK}C%^" fullword ascii
      $s20 = "_.gQA[ZIc" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      ( pe.imphash() == "89b43582b27abefb2b74684ab12a2f8e" or 8 of them )
}