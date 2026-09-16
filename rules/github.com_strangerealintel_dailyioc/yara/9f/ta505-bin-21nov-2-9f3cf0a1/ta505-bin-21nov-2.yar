import "pe"
rule TA505_bin_21Nov_2 {
   meta:
      description = "vspub1.bin"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/58_158_177_102/status/1197432303057637377"
      date = "2019-11-21"
      hash1 = "54cc27076793d5de064813c61d52452d42f774d24b3859a63002d842914fd9cd"
   strings:
      $s1 = "glColor.dll" fullword ascii
      $s2 = "{sysdir}\\nvu*.exe" fullword ascii
      $s3 = "KLSUIrhekheirguhemure" fullword ascii
      $s4 = "tEo>qM" fullword ascii
      $s5 = "?\"?0?8?>?I?V?^?l?q?v?{?" fullword ascii
      $s6 = ";\";0;d;" fullword ascii
      $s7 = "T0p0v0|0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and
      ( pe.imphash() == "ff6dd5f31dd7c538ebc02542f09f4280" and pe.exports("setColor") or all of them )
}