import "pe"
rule sig_24952_files_csharp_streamer {
   meta:
      description = "24952-files - file cslite.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
      date = "2024-05-27"
      hash1 = "4103cc8017409963b417c87259af2a955653567cdbf7d5504198dd350f9ef9c1"
   strings:
      $s1 = "release.exe" fullword wide
      $s2 = "qqqH!!!" fullword ascii
      $s3 = "VVVe!!!" fullword ascii
      $s4 = "\\\\\\L!!!" fullword ascii
      $s5 = "2TlYH.DdI<" fullword ascii
      $s6 = "DDD9!!!" fullword ascii
      $s7 = "aaa@!!!" fullword ascii
      $s8 = "(7']*,D, " fullword ascii 
      $s9 = "* hpSr" fullword ascii
      $s10 = "iiirbbb" fullword ascii
      $s11 = "tttqwww" fullword ascii
      $s12 = "NydRunMb" fullword ascii
      $s13 = "INGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADD" ascii
      $s14 = "VVVLFFFP" fullword ascii
      $s15 = "INGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" fullword ascii
      $s16 = "PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADD" ascii
      $s17 = "PADPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADD" ascii
      $s18 = "_>eyeyF" fullword ascii
      $s19 = "absent sponsor" fullword wide
      $s20 = "1.4.1.0" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      ( pe.imphash() == "a2e2347c63992bb608dd91cddbd5798f" or 8 of them )
}