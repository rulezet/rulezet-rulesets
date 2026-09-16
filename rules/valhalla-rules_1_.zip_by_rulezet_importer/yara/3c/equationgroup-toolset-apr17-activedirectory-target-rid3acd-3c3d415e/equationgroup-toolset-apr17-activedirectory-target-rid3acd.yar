rule EquationGroup_Toolset_Apr17_ActiveDirectory_Target_RID3ACD : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "33c1b7fdee7c70604be1e7baa9eea231164e62d5d5090ce7f807f43229fe5c36"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "(&(objectCategory=person)(objectClass=user)(cn=" fullword wide
      $s2 = "(&(objectClass=user)(objectCategory=person)" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}