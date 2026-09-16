rule EquationGroup_Toolset_Apr17_Windows_Implant_RID3815 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 18:06:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d38ce396926e45781daecd18670316defe3caf975a3062470a87c1d181a61374"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "0#0)0/050;0M0Y0h0|0" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 50KB and all of them )
}