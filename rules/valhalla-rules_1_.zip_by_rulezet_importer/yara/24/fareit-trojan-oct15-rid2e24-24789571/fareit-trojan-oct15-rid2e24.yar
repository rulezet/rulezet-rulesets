rule Fareit_Trojan_Oct15_RID2E24 : DEMO EXE FILE MAL {
   meta:
      description = "Detects Fareit Trojan from Sep/Oct 2015 Wave"
      author = "Florian Roth"
      reference = "https://blogs.cisco.com/security/talos/fareit-analysis"
      date = "2015-10-18 11:01:51"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "230ca0beba8ae712cfe578d2b8ec9581ce149a62486bef209b04eb11d8c088c3"
      hash2 = "3477d6bfd8313d37fedbd3d6ba74681dd7cb59040cabc2991655bdce95a2a997"
      hash3 = "408fa0bd4d44de2940605986b554e8dab42f5d28a6a525b4bc41285e37ab488d"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ebai.exe" fullword wide
      $s2 = "Origina" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and $s1 in ( 0 .. 30000 ) and $s2 in ( 0 .. 30000 )
}