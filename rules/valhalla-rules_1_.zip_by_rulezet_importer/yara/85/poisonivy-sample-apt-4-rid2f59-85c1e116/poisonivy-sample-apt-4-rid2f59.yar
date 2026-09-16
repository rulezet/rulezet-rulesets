rule PoisonIvy_Sample_APT_4_RID2F59 : APT DEMO EXE FILE {
   meta:
      description = "Detects a PoisonIvy Sample APT"
      author = "Florian Roth"
      reference = "VT Analysis"
      date = "2015-06-03 11:53:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Microsoft Software installation Service" fullword wide
      $s1 = "idll.dll" fullword ascii
      $s2 = "mgmts.dll" fullword wide
      $s3 = "Microsoft(R) Windows(R)" fullword wide
      $s4 = "ServiceMain" fullword ascii
      $s5 = "Software installation Service" fullword wide
      $s6 = "SetServiceStatus" fullword ascii
      $s7 = "OriginalFilename" fullword wide
      $s8 = "ZwSetInformationProcess" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 7 of them
}