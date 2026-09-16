rule PoisonIvy_Sample_APT_RID2EC6 : APT DEMO EXE FILE {
   meta:
      description = "Detects a PoisonIvy APT malware group"
      author = "Florian Roth"
      reference = "VT Analysis"
      date = "2015-06-03 11:28:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "pidll.dll" fullword ascii
      $s1 = "sens32.dll" fullword wide
      $s3 = "FileDescription" fullword wide
      $s4 = "OriginalFilename" fullword wide
      $s5 = "ZwSetInformationProcess" fullword ascii
      $s9 = "Microsoft Media Device Service Provider" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 47KB and all of them
}