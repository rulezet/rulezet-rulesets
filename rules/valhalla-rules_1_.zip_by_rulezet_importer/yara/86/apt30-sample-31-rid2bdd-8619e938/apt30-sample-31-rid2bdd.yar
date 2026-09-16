rule APT30_Sample_31_RID2BDD : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\ZJRsv.tem" ascii
      $s1 = "forceguest" fullword ascii
      $s4 = "\\$NtUninstallKB570317$" ascii
      $s8 = "[Can'tGetIP]" fullword ascii
      $s14 = "QWERTY:,`/" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}