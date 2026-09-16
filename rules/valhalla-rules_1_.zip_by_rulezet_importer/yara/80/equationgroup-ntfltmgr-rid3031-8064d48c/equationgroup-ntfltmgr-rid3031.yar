rule EquationGroup_ntfltmgr_RID3031 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file ntfltmgr.sys"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 12:29:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ntfltmgr.sys" fullword wide
      $s2 = "ntfltmgr.pdb" fullword ascii
      $s4 = "Network Filter Manager" fullword wide
      $s5 = "Corporation. All rights reserved." fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them )
}