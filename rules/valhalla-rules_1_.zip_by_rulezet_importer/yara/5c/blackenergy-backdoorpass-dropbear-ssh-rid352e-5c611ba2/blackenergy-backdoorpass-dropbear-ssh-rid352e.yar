rule BlackEnergy_BackdoorPass_DropBear_SSH_RID352E : APT DEMO EXE FILE T1021_004 blackenergy {
   meta:
      description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy"
      author = "Florian Roth"
      reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
      date = "2016-01-03 16:02:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE, T1021_004, blackenergy"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "passDs5Bu9Te7" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and $s1
}