rule PoisonIvy_Sample_5_RID2E16 : APT DEMO EXE FILE {
   meta:
      description = "Detects PoisonIvy RAT sample set"
      author = "Florian Roth"
      reference = "VT Analysis"
      date = "2015-06-03 10:59:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Microsoft Software installation Service" fullword wide
      $s2 = "pidll.dll" fullword ascii
      $s3 = "\\mspmsnsv.dll" ascii
      $s4 = "\\sfc.exe" ascii
      $s13 = "ServiceMain" fullword ascii
      $s15 = "ZwSetInformationProcess" fullword ascii
      $s17 = "LookupPrivilegeValueA" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them
}