rule APT30_Sample_28_RID2BE3 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:41"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e62a63307deead5c9fcca6b9a2d51fb0"
      hash2 = "5b590798da581c894d8a87964763aa8b"
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "www.flyeagles.com" fullword ascii
      $s1 = "iexplore.exe" fullword ascii
      $s2 = "www.km-nyc.com" fullword ascii
      $s3 = "cmdLine.exe" fullword ascii
      $s4 = "Software\\Microsoft\\CurrentNetInf" fullword ascii
      $s5 = "/dizhi.gif" ascii
      $s6 = "/connect.gif" ascii
      $s7 = "USBTest.sys" fullword ascii
      $s8 = "/ver.htm" fullword ascii
      $s11 = "\\netscv.exe" ascii
      $s12 = "/app.htm" fullword ascii
      $s13 = "\\netsvc.exe" ascii
      $s14 = "/exe.htm" fullword ascii
      $s18 = "MicrosoftHaveAck" fullword ascii
      $s19 = "MicrosoftHaveExit" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and 7 of them
}