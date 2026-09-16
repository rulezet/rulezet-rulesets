rule APT30_Sample_16_RID2BE0 : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:25:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Temp1020.txt" ascii
      $s1 = "cmcbqyjs" fullword ascii
      $s2 = "SPVSWh\\" fullword ascii
      $s4 = "PSShxw@" fullword ascii
      $s5 = "VWhHw@" fullword ascii
      $s7 = "SVWhHw@" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}