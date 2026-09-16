rule APT30_Generic_B_RID2C16 : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0fcb4ffe2eb391421ec876286c9ddb6c"
      hash2 = "29395c528693b69233c1c12bef8a64b3"
      hash3 = "4c6b21e98ca03e0ef0910e07cef45dac"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Moziea/4.0" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}