rule SUSP_CMD_Var_Expansion_RID2F2B : DEMO FILE OFFICE SUSP {
   meta:
      description = "Detects Office droppers that include a variable expansion string"
      author = "Florian Roth"
      reference = "https://twitter.com/asfakian/status/1044859525675843585"
      date = "2018-09-26 11:45:41"
      score = 45
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, OFFICE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = " /V:ON" ascii wide fullword
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 500KB and $a1
}