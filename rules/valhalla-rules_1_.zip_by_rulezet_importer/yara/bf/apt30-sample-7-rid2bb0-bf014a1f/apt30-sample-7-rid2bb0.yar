rule APT30_Sample_7_RID2BB0 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:17:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "datain" fullword ascii
      $s3 = "C:\\Prog" ascii
      $s4 = "$LDDATA$" ascii
      $s5 = "Maybe a Encrypted Flash" fullword ascii
      $s6 = "Jean-loup Gailly" ascii
      $s8 = "deflate 1.1.3 Copyright" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}