rule APT30_Generic_G_RID2C1B : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:35:01"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%s\\%s\\%s=%s" fullword ascii
      $s1 = "Copy File %s OK!" fullword ascii
      $s2 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
      $s4 = "open=%s" fullword ascii
      $s5 = "Maybe a Encrypted Flash Disk" fullword ascii
      $s12 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}