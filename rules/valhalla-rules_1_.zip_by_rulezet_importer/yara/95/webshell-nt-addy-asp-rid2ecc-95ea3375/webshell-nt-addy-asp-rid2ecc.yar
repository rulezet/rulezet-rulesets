rule Webshell_NT_Addy_asp_RID2ECC : DEMO T1505_003 WEBSHELL {
   meta:
      description = "Semi-Auto-generated - file NT Addy.asp.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-03-29 11:29:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "NTDaddy v1.9 by obzerve of fux0r inc" 
      $s2 = "<ERROR: THIS IS NOT A TEXT FILE>" 
      $s4 = "RAW D.O.S. COMMAND INTERFACE" 
   condition: 
      1 of them
}