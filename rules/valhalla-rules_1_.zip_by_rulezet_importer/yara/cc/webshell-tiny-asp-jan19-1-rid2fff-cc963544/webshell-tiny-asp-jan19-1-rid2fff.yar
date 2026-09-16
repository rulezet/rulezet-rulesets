rule Webshell_Tiny_ASP_Jan19_1_RID2FFF : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects a Tiny ASP webshell"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-01-16 12:21:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ddcae07ec497ea43ed38fcd6379b2a35776bc2e45b8c5b0267310e92ba3b30cc"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Execute Request" ascii wide nocase
   condition: 
      uint16 ( 0 ) == 0x253c and filesize < 150 and 1 of them
}