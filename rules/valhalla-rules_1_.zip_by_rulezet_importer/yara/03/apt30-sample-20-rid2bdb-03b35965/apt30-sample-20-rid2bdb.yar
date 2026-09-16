rule APT30_Sample_20_RID2BDB : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:21"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "dizhi.gif" fullword ascii
      $s2 = "Mozilla/u" ascii
      $s3 = "XicrosoftHaveAck" ascii
      $s4 = "flyeagles" ascii
      $s10 = "iexplore." ascii
      $s13 = "WindowsGV" fullword ascii
      $s16 = "CatePipe" fullword ascii
      $s17 = "'QWERTY:/webpage3" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}