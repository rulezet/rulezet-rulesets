rule APT30_Generic_6_RID2C0A : APT DEMO FILE G0013 GEN {
   meta:
      description = "FireEye APT30 Report Sample - from files 168d207d0599ed0bb5bcfca3b3e7a9d3, 1e6ee89fddcf23132ee12802337add61, 5dd625af837e164dd2084b1f44a45808"
      author = "Florian Roth"
      reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
      date = "2015-04-03 09:32:11"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "2c5e347083b77c9ead9e75d41e2fabe096460bba"
      hash2 = "5d39a567b50c74c4a921b5f65713f78023099933"
      tags = "APT, DEMO, FILE, G0013, GEN"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "GetStar" fullword
      $s1 = ".rdUaS" fullword
      $s2 = "%sOTwp/&A\\L" fullword
      $s3 = "a Encrt% Flash Disk" fullword
      $s4 = "ypeAutoRuChec" fullword
      $s5 = "NoDriveT" fullword
   condition: 
      filesize < 100KB and uint16 ( 0 ) == 0x5A4D and all of them
}