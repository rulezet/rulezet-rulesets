rule HKTL_SqlMap_backdoor_RID2E95 : DEMO FILE HKTL SUSP {
   meta:
      description = "Detects SqlMap backdoors"
      author = "Florian Roth"
      reference = "https://github.com/sqlmapproject/sqlmap"
      date = "2018-10-09 11:20:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, HKTL, SUSP"
      minimum_yara = "3.5.0"
      
   condition: 
      ( uint32 ( 0 ) == 0x8e859c07 or uint32 ( 0 ) == 0x2d859c07 or uint32 ( 0 ) == 0x92959c07 or uint32 ( 0 ) == 0x929d9c07 or uint32 ( 0 ) == 0x29959c07 or uint32 ( 0 ) == 0x2b8d9c07 or uint32 ( 0 ) == 0x2b859c07 or uint32 ( 0 ) == 0x28b59c07 ) and filesize < 2KB
}