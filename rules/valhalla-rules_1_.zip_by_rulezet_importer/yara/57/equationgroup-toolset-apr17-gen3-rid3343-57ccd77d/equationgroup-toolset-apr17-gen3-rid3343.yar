rule EquationGroup_Toolset_Apr17_Gen3_RID3343 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 14:40:21"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "270850303e662be53d90fa60a9e5f4bd2bfb95f92a046c77278257631d9addf4"
      hash2 = "7a086c0acb6df1fa304c20733f96e898d21ca787661270f919329fadfb930a6e"
      hash3 = "c236e0d9c5764f223bd3d99f55bd36528dfc0415e14f5fde1e5cdcada14f4ec0"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Logon failed.  Kerberos ticket not yet valid (target and KDC times not synchronized)" fullword ascii
      $s2 = "[-] Could not set \"CredentialType\"" fullword ascii
      $op1 = { 46 83 c4 0c 83 fe 0c 0f 8c 5e ff ff ff b8 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 150KB and 2 of them )
}