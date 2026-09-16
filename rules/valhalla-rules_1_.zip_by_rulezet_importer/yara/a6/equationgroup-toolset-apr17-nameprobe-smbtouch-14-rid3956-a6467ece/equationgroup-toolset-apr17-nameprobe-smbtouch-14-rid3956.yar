rule EquationGroup_Toolset_Apr17__NameProbe_SMBTOUCH_14_RID3956 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:59:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fbe3a4501654438f502a93f51b298ff3abf4e4cad34ce4ec0fad5cb5c2071597"
      hash2 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "DEC Pathworks TCPIP service on Windows NT" fullword ascii
      $s2 = "<\\\\__MSBROWSE__> G" fullword ascii
      $s3 = "<IRISNAMESERVER>" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}