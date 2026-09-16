rule APT30_Sample_24_RID2BDF : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:01"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "dizhi.gif" fullword ascii
      $s3 = "Mozilla/4.0" fullword ascii
      $s4 = "lyeagles" fullword ascii
      $s6 = "HHOSTR" ascii
      $s7 = "#MicrosoftHaveAck7" ascii
      $s8 = "iexplore." fullword ascii
      $s17 = "ModuleH" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}