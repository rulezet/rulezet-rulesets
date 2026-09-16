rule SUSP_Katz_PDB {
   meta:
      description = "Detects suspicious PDB in file"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-02-04"
      hash1 = "6888ce8116c721e7b2fc3d7d594666784cf38a942808f35e309a48e536d8e305"
      id = "79f4f07c-b234-5203-a2ab-aba4a9cb9f8d"
   strings:
      $s1 = /\\Release\\[a-z]{0,8}katz.pdb/
      $s2 = /\\Debug\\[a-z]{0,8}katz.pdb/
   condition:
      uint16(0) == 0x5a4d and filesize < 6000KB and all of them
}