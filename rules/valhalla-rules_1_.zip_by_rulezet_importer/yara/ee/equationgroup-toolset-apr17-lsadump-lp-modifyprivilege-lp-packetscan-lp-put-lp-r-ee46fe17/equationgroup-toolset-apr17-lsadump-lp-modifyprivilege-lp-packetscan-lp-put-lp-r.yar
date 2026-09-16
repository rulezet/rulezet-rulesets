rule EquationGroup_Toolset_Apr17__LSADUMP_Lp_ModifyPrivilege_Lp_PacketScan_Lp_put_Lp_RemoteExecute_Lp_Windows_Lp_wmi_Lp_9_RID53B6 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 09:10:30"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
      hash2 = "d92928a867a685274b0a74ec55c0b83690fca989699310179e184e2787d47f48"
      hash3 = "2d963529e6db733c5b74db1894d75493507e6e40da0de2f33e301959b50f3d32"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Injection Lib -  " wide
      $x2 = "LSADUMP - - ERROR" wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 1 of them )
}