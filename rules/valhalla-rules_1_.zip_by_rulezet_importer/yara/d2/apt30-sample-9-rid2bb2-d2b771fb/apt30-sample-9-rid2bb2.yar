rule APT30_Sample_9_RID2BB2 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:17:31"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Windo" ascii
      $s2 = "oHHOSTR" ascii
      $s3 = "Softwa]\\Mic" ascii
      $s4 = "Startup'T" ascii
      $s6 = "Ora\\%^" ascii
      $s7 = "\\Ohttp=r" ascii
      $s17 = "help32Snapshot0L" ascii
      $s18 = "TimUmoveH" ascii
      $s20 = "WideChc[lobalAl" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}