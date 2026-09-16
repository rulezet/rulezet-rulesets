rule APT30_Sample_27_RID2BE2 : APT DEMO FILE G0013 {
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
      $s0 = "Mozilla/4.0" fullword ascii
      $s1 = "dizhi.gif" fullword ascii
      $s5 = "oftHaveAck+" ascii
      $s10 = "HlobalAl" fullword ascii
      $s13 = "$NtRND1$" fullword ascii
      $s14 = "_NStartup" ascii
      $s16 = "GXSYSTEM" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}