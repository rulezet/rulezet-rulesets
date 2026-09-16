rule Exp_EPS_CVE20152545_RID2C5A : DEMO EXPLOIT FILE OFFICE {
   meta:
      description = "Detects EPS Word Exploit"
      author = "Florian Roth"
      reference = "Internal Research - ME"
      date = "2017-07-19 09:45:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, FILE, OFFICE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "word/media/image1.eps" ascii
      $s2 = "-la;7(la+" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and ( $s1 and #s2 > 20 )
}