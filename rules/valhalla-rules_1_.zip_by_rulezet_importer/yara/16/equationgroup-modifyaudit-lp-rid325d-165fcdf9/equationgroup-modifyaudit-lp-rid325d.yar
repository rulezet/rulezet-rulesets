rule EquationGroup_modifyAudit_Lp_RID325D : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file modifyAudit_Lp.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "2a1f2034e80421359e3bf65cbd12a55a95bd00f2eb86cf2c2d287711ee1d56ad"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Read of audit related process memory failed" fullword wide
      $s2 = "** This may indicate that another copy of modify_audit is already running **" fullword wide
      $s3 = "Pattern match of code failed" fullword wide
      $s4 = "Base for necessary auditing dll not found" fullword wide
      $s5 = "Security auditing has been disabled" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 3 of them ) or ( all of them )
}