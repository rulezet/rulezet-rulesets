rule Codoso_CustomTCP_RID2D39 : DEMO EXE FILE G0073 MAL {
   meta:
      description = "Codoso CustomTCP Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G0073, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s4 = "wnyglw" fullword ascii
      $s5 = "WorkerRun" fullword ascii
      $s7 = "boazdcd" fullword ascii
      $s8 = "wayflw" fullword ascii
      $s9 = "CODETABL" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 405KB and all of them
}