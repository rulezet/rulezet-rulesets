rule EquationGroup_modifyAudit_Implant_RID3476 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file modifyAudit_Implant.dll"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 15:31:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "b7902809a15c4c3864a14f009768693c66f9e9234204b873d29a87f4c3009a50"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "LSASS.EXE" fullword wide
      $s2 = "hNtQueryInformationProcess" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
      $s4 = ".?AVFeFinallyFailure@@" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 90KB and ( all of ( $s* ) ) ) or ( all of them )
}