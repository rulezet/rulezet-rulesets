rule EquationGroup_Toolset_Apr17_Educatedscholartouch_1_0_0_RID3BD2 : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 20:45:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "f4b958a0d3bb52cb34f18ea293d43fa301ceadb4a259d3503db912d0a9a1e4d8"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[!] A vulnerable target will not respond." fullword ascii
      $x2 = "[-] Target NOT Vulernable" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 30KB and 1 of them )
}