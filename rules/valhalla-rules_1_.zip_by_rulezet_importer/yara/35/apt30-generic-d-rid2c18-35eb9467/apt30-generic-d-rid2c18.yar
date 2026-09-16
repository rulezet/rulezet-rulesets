rule APT30_Generic_D_RID2C18 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:31"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "35dfb55f419f476a54241f46e624a1a4"
      hash2 = "4fffcbdd4804f6952e0daf2d67507946"
      hash3 = "597805832d45d522c4882f21db800ecf"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Windows Security Service Feedback" fullword wide
      $s1 = "wssfmgr.exe" fullword wide
      $s2 = "\\rb.htm" ascii
      $s3 = "rb.htm" fullword ascii
      $s4 = "cook5" ascii
      $s5 = "5, 4, 2600, 0" fullword wide
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}