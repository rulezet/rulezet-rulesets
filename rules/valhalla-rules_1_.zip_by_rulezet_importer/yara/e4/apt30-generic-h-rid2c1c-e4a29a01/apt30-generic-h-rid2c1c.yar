rule APT30_Generic_H_RID2C1C : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:35:11"
      score = 85
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2a4c8752f3e7fde0139421b8d5713b29c720685d"
      hash2 = "4350e906d590dca5fcc90ed3215467524e0a4e3d"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\Temp1020.txt" ascii
      $s1 = "Xmd.Txe" fullword ascii
      $s2 = "\\Internet Exp1orer" ascii
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}