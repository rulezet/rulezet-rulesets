rule SUSP_Bad_PDF_RID2AFB : DEMO FILE SUSP {
   meta:
      description = "Detects PDF that embeds code to steal NTLM hashes"
      author = "Florian Roth, Markus Neis"
      reference = "Internal Research"
      date = "2018-05-03 08:47:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d8c502da8a2b8d1c67cb5d61428f273e989424f319cfe805541304bdb7b921a8"
      tags = "DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "         /F (http//" ascii
      $s2 = "        /F (\\\\\\\\" ascii
      $s3 = "<</F (\\\\" ascii
   condition: 
      ( uint32 ( 0 ) == 0x46445025 or uint32 ( 0 ) == 0x4450250a ) and 1 of them
}