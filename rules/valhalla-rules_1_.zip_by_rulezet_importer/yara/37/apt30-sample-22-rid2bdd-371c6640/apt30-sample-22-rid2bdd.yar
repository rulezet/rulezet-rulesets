rule APT30_Sample_22_RID2BDD : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:24:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "(\\TEMP" fullword ascii
      $s2 = "Windows\\Cur" fullword ascii
      $s3 = "LSSAS.exeJ" fullword ascii
      $s4 = "QC:\\WINDOWS" fullword ascii
      $s5 = "System Volume" fullword ascii
      $s8 = "PROGRAM FILE" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}