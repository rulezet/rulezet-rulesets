rule APT30_Sample_1_RID2BAA : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:11"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "#hostid" fullword ascii
      $s1 = "\\Windows\\C" ascii
      $s5 = "TimUmove" fullword ascii
      $s6 = "Moziea/4.0 (c" fullword ascii
      $s7 = "StartupNA" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}