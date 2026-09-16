rule APT30_Sample_30_RID2BDC : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)" fullword wide
      $s3 = "RnhwtxtkyLRRMf{jJ}ny" fullword ascii
      $s4 = "RnhwtxtkyLRRJ}ny" fullword ascii
      $s5 = "ZRLDownloadToFileA" fullword ascii
      $s9 = "5.1.2600.2180" fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}