rule APT30_Sample_34_RID2BE0 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:11"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "dizhi.gif" ascii
      $s1 = "eagles.vip.nse" ascii
      $s4 = "o%S:S0" ascii
      $s5 = "la/4.0" ascii
      $s6 = "s#!<4!2>s02==<'s1" ascii
      $s7 = "HlobalAl" ascii
      $s9 = "vcMicrosoftHaveAck7" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}