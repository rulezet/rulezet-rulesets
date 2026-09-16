rule EquationGroup_PC_Level4_flav_exe_RID338A : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file PC_Level4_flav_exe"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 14:52:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "33ba9f103186b6e52d8d69499512e7fbac9096e7c5278838127488acc3b669a9"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Extended Memory Runtime Process" fullword wide
      $s2 = "memess.exe" fullword wide
      $s3 = "\\\\.\\%hs" fullword ascii
      $s4 = ".?AVOpenSocket@@" fullword ascii
      $s5 = "Corporation. All rights reserved." fullword wide
      $s6 = "itanium" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}