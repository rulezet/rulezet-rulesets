rule APT30_Sample_25_RID2BE0 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\WINDOWS" fullword ascii
      $s2 = "aragua" fullword ascii
      $s4 = "\\driver32\\7$" ascii
      $s8 = "System V" fullword ascii
      $s9 = "Compu~r" fullword ascii
      $s10 = "PROGRAM L" fullword ascii
      $s18 = "GPRTMAX" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}