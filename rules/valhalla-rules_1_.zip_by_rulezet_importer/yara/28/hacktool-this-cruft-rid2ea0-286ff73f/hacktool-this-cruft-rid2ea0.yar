rule Hacktool_This_Cruft_RID2EA0 : APT DEMO EXE FILE G0041 {
   meta:
      description = "Detects string 'This cruft' often used in hack tools like netcat or cryptcat and also mentioned in Project Sauron report"
      author = "Florian Roth"
      reference = "https://securelist.com/faq-the-projectsauron-apt/75533/"
      date = "2016-08-08 11:22:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      tags = "APT, DEMO, EXE, FILE, G0041"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "This cruft" fullword
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and $x1 )
}