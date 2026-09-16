rule APT30_Generic_1_RID2C05 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:31:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cb4263cab467845dae9fae427e3bbeb31c6a14c2"
      hash2 = "b69b95db8a55a050d6d6c0cba13d73975b8219ca"
      hash3 = "5c29e21bbe8873778f9363258f5e570dddcadeb9"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "%s\\%s.txt" fullword
      $s1 = "\\ldsysinfo.txt" 
      $s4 = "(Extended Wansung)" fullword
      $s6 = "Computer Name:" fullword
      $s7 = "%s %uKB %04u-%02u-%02u %02u:%02u" fullword
      $s8 = "ASSAMESE" fullword
      $s9 = "BELARUSIAN" fullword
      $s10 = "(PR China)" fullword
      $s14 = "(French)" fullword
      $s15 = "AdvancedServer" fullword
      $s16 = "DataCenterServer" fullword
      $s18 = "(Finland)" fullword
      $s19 = "%s %04u-%02u-%02u %02u:%02u" fullword
      $s20 = "(Chile)" fullword
   condition: 
      filesize < 250KB and uint16 ( 0 ) == 0x5A4D and all of them
}