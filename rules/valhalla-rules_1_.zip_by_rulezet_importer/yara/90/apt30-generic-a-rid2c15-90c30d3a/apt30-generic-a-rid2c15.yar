rule APT30_Generic_A_RID2C15 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9f49aa1090fa478b9857e15695be4a89f8f3e594"
      hash2 = "396116cfb51cee090822913942f6ccf81856c2fb"
      hash3 = "fef9c3b4b35c226501f7d60816bb00331a904d5b"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "WPVWhhiA" fullword ascii
      $s6 = "VPWVhhiA" fullword ascii
      $s11 = "VPhhiA" fullword ascii
      $s12 = "uUhXiA" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}