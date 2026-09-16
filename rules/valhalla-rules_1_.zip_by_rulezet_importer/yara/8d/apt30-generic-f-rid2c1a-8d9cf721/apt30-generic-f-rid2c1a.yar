rule APT30_Generic_F_RID2C1A : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:34:51"
      score = 95
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "09010917cd00dc8ddd21aeb066877aa2"
      hash2 = "4c10a1efed25b828e4785d9526507fbc"
      hash3 = "b7b282c9e3eca888cbdb5a856e07e8bd"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\~zlzl.exe" ascii
      $s2 = "\\Internet Exp1orer" ascii
      $s3 = "NodAndKabIsExcellent" fullword ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}