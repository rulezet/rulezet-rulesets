rule EquationGroup_Toolset_Apr17_yak_min_install_RID3834 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:11:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f67214083d60f90ffd16b89a0ce921c98185b2032874174691b720514b1fe99e"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "driver start" fullword ascii
      $s2 = "DeviceIoControl Error: %d" fullword ascii
      $s3 = "Phlook" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}