rule EquationGroup_Toolset_Apr17_DmGz_Target_RID362E : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:44:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "5964966041f93d5d0fb63ce4a85cf9f7a73845065e10519b0947d4a065fdbdf2"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\\\.\\%ls" fullword ascii
      $s3 = "6\"6<6C6H6M6Z6f6t6" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 80KB and all of them )
}