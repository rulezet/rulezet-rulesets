rule APT30_Sample_4_RID2BAD : APT DEMO FILE G0013 {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:16:41"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "GetStartupIn" ascii
      $s1 = "enMutex" ascii
      $s2 = "tpsvimi" ascii
      $s3 = "reateProcesy" ascii
      $s5 = "FreeLibr1y*S" ascii
      $s6 = "foAModuleHand" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}