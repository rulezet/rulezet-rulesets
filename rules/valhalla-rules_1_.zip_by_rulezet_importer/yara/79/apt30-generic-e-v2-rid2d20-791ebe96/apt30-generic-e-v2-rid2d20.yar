rule APT30_Generic_E_v2_RID2D20 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 10:18:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Nkfvtyvn}duf_Z}{Ys" fullword ascii
      $s1 = "Nkfvtyvn}*Zrswru1i" fullword ascii
      $s2 = "Nkfvtyvn}duf_Z}{V" fullword ascii
      $s3 = "Nkfvtyvn}*ZrswrumT\\b" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}