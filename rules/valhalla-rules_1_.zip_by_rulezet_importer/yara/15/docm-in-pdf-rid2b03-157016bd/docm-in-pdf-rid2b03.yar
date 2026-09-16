rule Docm_in_PDF_RID2B03 : DEMO FILE SUSP {
   meta:
      description = "Detects an embedded DOCM in PDF combined with OpenAction"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-15 08:48:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = /<<\/Names\[\([\w]{1,12}.docm\)/ ascii
      $a2 = "OpenAction" ascii fullword
      $a3 = "JavaScript" ascii fullword
   condition: 
      uint32 ( 0 ) == 0x46445025 and all of them
}