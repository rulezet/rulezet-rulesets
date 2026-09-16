rule Sofacy_Mal2_RID2B21 : APT DEMO EXE FILE G0007 RUSSIA {
   meta:
      description = "Sofacy Group Malware Sample 2"
      author = "Florian Roth"
      reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
      date = "2015-06-19 08:53:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, G0007, RUSSIA"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "PROJECT\\XAPS_OBJECTIVE_DLL\\" ascii
      $x2 = "XAPS_OBJECTIVE.dll" fullword ascii
      $s1 = "i`m wait" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( 1 of ( $x* ) ) and $s1
}