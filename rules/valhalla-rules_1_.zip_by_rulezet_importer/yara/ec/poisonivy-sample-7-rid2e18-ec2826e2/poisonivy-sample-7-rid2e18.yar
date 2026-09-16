rule PoisonIvy_Sample_7_RID2E18 : APT DEMO EXE FILE {
   meta:
      description = "Detects PoisonIvy RAT sample set"
      author = "Florian Roth"
      reference = "VT Analysis"
      date = "2015-06-03 10:59:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Microsoft Software installation Service" fullword wide
      $s2 = "pidll.dll" fullword ascii
      $s10 = "ServiceMain" fullword ascii
      $s11 = "ZwSetInformationProcess" fullword ascii
      $s12 = "Software installation Service" fullword wide
      $s13 = "Microsoft(R) Windows(R) Operating System" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}