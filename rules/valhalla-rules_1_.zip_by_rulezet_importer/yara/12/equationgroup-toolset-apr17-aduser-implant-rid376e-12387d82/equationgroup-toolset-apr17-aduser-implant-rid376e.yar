rule EquationGroup_Toolset_Apr17_AdUser_Implant_RID376E : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 17:38:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fd2efb226969bc82e2e38769a10a8a751138db69f4594a8de4b3c0522d4d885f"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s2 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 40KB and all of them )
}