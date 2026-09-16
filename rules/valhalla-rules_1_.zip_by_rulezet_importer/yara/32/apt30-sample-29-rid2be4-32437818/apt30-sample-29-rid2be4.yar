rule APT30_Sample_29_RID2BE4 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "LSSAS.exe" fullword ascii
      $s1 = "Software\\Microsoft\\FlashDiskInf" fullword ascii
      $s2 = ".petite" fullword ascii
      $s3 = "MicrosoftFlashExit" fullword ascii
      $s4 = "MicrosoftFlashHaveExit" fullword ascii
      $s5 = "MicrosoftFlashHaveAck" fullword ascii
      $s6 = "\\driver32" ascii
      $s7 = "MicrosoftFlashZJ" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}