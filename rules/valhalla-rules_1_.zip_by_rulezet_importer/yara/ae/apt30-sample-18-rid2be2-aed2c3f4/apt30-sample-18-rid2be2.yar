rule APT30_Sample_18_RID2BE2 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:31"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "w.km-nyc.com" fullword ascii
      $s1 = "tscv.exe" fullword ascii
      $s2 = "Exit/app.htm" ascii
      $s3 = "UBD:\\D" ascii
      $s4 = "LastError" ascii
      $s5 = "MicrosoftHaveAck" ascii
      $s7 = "HHOSTR" ascii
      $s20 = "XPL0RE." ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}