rule APT30_Generic_7_RID2C0B : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample - from files 853a20f5fc6d16202828df132c41a061, 9c0cad1560cd0ffe2aa570621ef7d0a0, b590c15499448639c2748ff9e0d214b2"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:32:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "e814914079af78d9f1b71000fee3c29d31d9b586"
      hash2 = "0263de239ccef669c47399856d481e3361408e90"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Xjapor_*ata" fullword
      $s2 = "Xjapor_o*ata" fullword
      $s4 = "Ouopai" fullword
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}