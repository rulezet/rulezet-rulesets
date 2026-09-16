rule b374k_back_connect_RID2DB5 : APT DEMO EXE FILE T1068 {
   meta:
      description = "Detects privilege escalation tool"
      author = "Florian Roth"
      reference = "Internal Analysis"
      date = "2016-08-18 10:43:21"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c8e16f71f90bbaaef27ccaabb226b43762ca6f7e34d7d5585ae0eb2d36a4bae5"
      tags = "APT, DEMO, EXE, FILE, T1068"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "AddAtomACreatePro" fullword ascii
      $s2 = "shutdow" fullword ascii
      $s3 = "/config/i386" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 10KB and all of them )
}