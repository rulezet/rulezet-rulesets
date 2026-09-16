rule EquationGroup_EquationDrug_msgkd_RID3410 : APT DEMO EXE FILE {
   meta:
      description = "EquationGroup Malware - file msgkd.ex_"
      author = "Florian Roth"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/messagefinale/"
      date = "2017-01-13 15:14:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "25eec68fc9f0d8d1b5d72c9eae7bee29035918e9dcbeab13e276dec4b2ad2a56"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "KEysud" fullword ascii
      $s2 = "XWWWPWS" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}