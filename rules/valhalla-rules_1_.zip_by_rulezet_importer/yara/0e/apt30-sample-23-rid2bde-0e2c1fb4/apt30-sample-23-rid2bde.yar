rule APT30_Sample_23_RID2BDE : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "hostid" ascii
      $s1 = "\\Window" ascii
      $s2 = "%u:%u%s" fullword ascii
      $s5 = "S2tware\\Mic" ascii
      $s6 = "la/4.0 (compa" ascii
      $s7 = "NameACKernel" fullword ascii
      $s12 = "ToWideChc[lo" fullword ascii
      $s14 = "help32SnapshotfL" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}