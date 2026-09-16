rule SUSP_Katz_PDB_RID2B8A : DEMO EXE FILE SUSP {
   meta:
      description = "Detects suspicious PDB in file"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-02-04 09:10:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6888ce8116c721e7b2fc3d7d594666784cf38a942808f35e309a48e536d8e305"
      tags = "DEMO, EXE, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = /\\Release\\[a-z]{0,8}katz.pdb/ 
      $s2 = /\\Debug\\[a-z]{0,8}katz.pdb/ 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 6000KB and all of them
}