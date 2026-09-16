rule EquationGroup_Toolset_Apr17_Dsz_Implant_RID365B : APT DEMO EXE FILE {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15 16:52:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fbe103fac45abe4e3638055a3cac5e7009166f626cf2d3049fb46f3b53c1057f"
      hash2 = "ad1dddd11b664b7c3ad6108178a8dade0a6d9795358c4a7cedbe789c62016670"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%02u:%02u:%02u.%03u-%4u: " fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}