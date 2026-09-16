rule APT30_Sample_26_RID2BE1 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "forcegue" fullword ascii
      $s3 = "Windows\\Cur" fullword ascii
      $s4 = "System Id" fullword ascii
      $s5 = "Software\\Mic" fullword ascii
      $s6 = "utiBy0ToWideCh&$a" fullword ascii
      $s10 = "ModuleH" fullword ascii
      $s15 = "PeekNamed6G" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}